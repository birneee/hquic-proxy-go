package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/birneee/hquic-proxy-go/common"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/handover"
	"github.com/lucas-clemente/quic-go/logging"
	"net"
	"os"
)

const HQUICProxyALPN = "qproxy"

type proxy struct {
	listener                quic.EarlyListener
	nextControlSessionId    uint64
	nextProxySessionId      uint64
	logger                  common.Logger
	nextProxyConf           *quic.ProxyConfig
	handoverOverwriteConfig *HandoverOverwriteConfig
}

type HandoverOverwriteConfig struct {
	ClientSideInitialReceiveWindow    uint64
	ServerSideInitialReceiveWindow    uint64
	ServerSideMaxReceiveWindow        uint64
	ClientSideInitialCongestionWindow uint32
}

func RunProxy(addr net.UDPAddr, controlTlsConfig *tls.Config, controlConfig *quic.Config, nextProxyConfig *quic.ProxyConfig, overwriteConfig *HandoverOverwriteConfig) error {

	if len(controlTlsConfig.NextProtos) == 0 {
		controlTlsConfig.NextProtos = []string{HQUICProxyALPN}
	}

	listener, err := quic.ListenAddrEarly(addr.String(), controlTlsConfig, controlConfig)
	if err != nil {
		return err
	}

	p := &proxy{
		listener:                listener,
		nextControlSessionId:    0,
		logger:                  common.DefaultLogger, //TODO cli option for prefix
		nextProxyConf:           nextProxyConfig,
		handoverOverwriteConfig: overwriteConfig,
	}

	fmt.Printf("starting proxy with pid %d, port %d, cc cubic\n", os.Getpid(), addr.Port)
	p.run()

	return nil
}

func (p *proxy) acceptControlSession() (*controlSession, error) {
	quicSession, err := p.listener.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	controlSessionID := p.nextControlSessionId
	p.nextControlSessionId += 1
	return newControlSession(controlSessionID, quicSession, p.logger.WithPrefix(fmt.Sprintf("control_session %d", controlSessionID))), nil
}

func (p *proxy) run() {
	for {
		controlSession, err := p.acceptControlSession()
		if err != nil {
			panic(err)
		}
		controlSession.logger.Infof("open")
		handoverState, err := controlSession.readHandoverStateAndClose()
		if err != nil {
			controlSession.logger.Errorf("failed to read handover state: %s", err)
			continue
		}
		controlSession.logger.Infof("handover state received")
		controlSession.logger.Infof("closed")
		proxySessionID := p.nextProxySessionId
		p.nextProxySessionId += 1
		err = p.runProxySession(handoverState, proxySessionID, controlSession.quicSession.RemoteAddr().(*net.UDPAddr))
		if err != nil {
			controlSession.logger.Errorf("failed to run proxy session: %s", err)
			continue
		}
	}
}

func (p *proxy) runProxySession(state *handover.State, sessionID uint64, requesterAddr *net.UDPAddr) error {
	// change handover state client ip, because client might not know
	{
		clientAddr, err := net.ResolveUDPAddr("udp", state.ClientAddress)
		if err != nil {
			return err
		}
		if clientAddr.IP.IsUnspecified() {
			//TODO this this does not work through NATs, client should multiplex connections
			state.ClientAddress = (&net.UDPAddr{IP: requesterAddr.IP, Port: clientAddr.Port}).String()
		}
	}

	logger := p.logger.WithPrefix(fmt.Sprintf("proxy_session %d", sessionID))
	tracer := common.NewMigrationTracer(func(addr net.Addr) {
		logger.Debugf("migrated to %s\n", addr)
	})

	toServerConf := &quic.Config{}
	if p.nextProxyConf != nil {
		toServerConf.Proxy = p.nextProxyConf
		toServerConf.EnableActiveMigration = true
		toServerConf.IgnoreReceived1RTTPacketsUntilFirstPathMigration = true
	}
	toServerConf.Tracer = tracer
	toServerState := state.Clone()
	if p.handoverOverwriteConfig != nil {
		if p.handoverOverwriteConfig.ServerSideInitialReceiveWindow != 0 {
			toServerConf.InitialStreamReceiveWindow = p.handoverOverwriteConfig.ServerSideInitialReceiveWindow
			toServerConf.InitialConnectionReceiveWindow = uint64(float64(p.handoverOverwriteConfig.ServerSideInitialReceiveWindow) * quic.ConnectionFlowControlMultiplier)
			//TODO adjust transport parameters of state without destroying further handovers
		}
		if p.handoverOverwriteConfig.ServerSideMaxReceiveWindow != 0 {
			toServerConf.MaxStreamReceiveWindow = p.handoverOverwriteConfig.ServerSideMaxReceiveWindow
			toServerConf.MaxConnectionReceiveWindow = uint64(float64(p.handoverOverwriteConfig.ServerSideMaxReceiveWindow) * quic.ConnectionFlowControlMultiplier)
		}
	}
	sessionToServer, err := quic.RestoreSessionFromHandoverState(*toServerState, logging.PerspectiveClient, toServerConf, fmt.Sprintf("proxy_session %d (to server)", sessionID))
	if err != nil {
		return err
	}

	toClientConf := &quic.Config{}
	toClientConf.Tracer = tracer
	toClientState := state.Clone()
	if p.handoverOverwriteConfig != nil {
		if p.handoverOverwriteConfig.ClientSideInitialReceiveWindow != 0 {
			toClientState.ServerTransportParameters.InitialMaxStreamDataBidiLocal = quic.ByteCount(p.handoverOverwriteConfig.ClientSideInitialReceiveWindow)
			toClientState.ServerTransportParameters.InitialMaxStreamDataBidiRemote = quic.ByteCount(p.handoverOverwriteConfig.ClientSideInitialReceiveWindow)
			toClientState.ServerTransportParameters.InitialMaxStreamDataUni = quic.ByteCount(p.handoverOverwriteConfig.ClientSideInitialReceiveWindow)
			toClientState.ServerTransportParameters.InitialMaxData = quic.ByteCount(float64(p.handoverOverwriteConfig.ClientSideInitialReceiveWindow) * quic.ConnectionFlowControlMultiplier)
			toClientState.ClientTransportParameters.InitialMaxStreamDataBidiLocal = quic.ByteCount(p.handoverOverwriteConfig.ClientSideInitialReceiveWindow)
			toClientState.ClientTransportParameters.InitialMaxStreamDataBidiRemote = quic.ByteCount(p.handoverOverwriteConfig.ClientSideInitialReceiveWindow)
			toClientState.ClientTransportParameters.InitialMaxStreamDataUni = quic.ByteCount(p.handoverOverwriteConfig.ClientSideInitialReceiveWindow)
			toClientState.ClientTransportParameters.InitialMaxData = quic.ByteCount(float64(p.handoverOverwriteConfig.ClientSideInitialReceiveWindow) * quic.ConnectionFlowControlMultiplier)
			//TODO adjust transport parameters of state without destroying further handovers; further handovers currently do not work
		}
		if p.handoverOverwriteConfig.ClientSideInitialCongestionWindow != 0 {
			toClientConf.InitialCongestionWindow = p.handoverOverwriteConfig.ClientSideInitialCongestionWindow
		}
	}
	sessionToClient, err := quic.RestoreSessionFromHandoverState(*toClientState, logging.PerspectiveServer, toClientConf, fmt.Sprintf("proxy_session %d (to client)", sessionID))
	if err != nil {
		return err
	}

	proxySession := proxySession{
		sessionID:           sessionID,
		quicSessionToServer: sessionToServer,
		quicSessionToClient: sessionToClient,
		logger:              logger,
	}

	go proxySession.run()
	return nil
}
