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

type proxy struct {
	listener                       quic.Listener
	conf                           quic.Config
	nextControlSessionId           uint64
	nextProxySessionId             uint64
	logger                         common.Logger
	nextProxyConf                  *quic.ProxyConfig
	clientSideInitialReceiveWindow uint64
	serverSideInitialReceiveWindow uint64
	serverSideMaxReceiveWindow     uint64
}

// RunProxy starts a new proxy
// nextProxyAddr the address of an additional, server-side proxy to add
// if nextProxyAddr is nil, don't add a proxy
// if clientSideInitialReceiveWindow is 0, use window from handover state
// if serverSideInitialReceiveWindow is 0, use window from handover state
func RunProxy(addr net.UDPAddr, tlsProxyCertFile string, tlsProxyKeyFile string, nextProxyAddr *net.UDPAddr, tlsNextProxyCertFile string, initialCongestionWindow uint32, clientSideInitialReceiveWindow uint64, serverSideInitialReceiveWindow uint64, serverSideMaxReceiveWindow uint64) {

	//TODO make cli options
	conf := quic.Config{
		InitialCongestionWindow: initialCongestionWindow,
		KeepAlive:               true,
	}

	//TODO make CLI option
	tlsCert, err := tls.LoadX509KeyPair(tlsProxyCertFile, tlsProxyKeyFile)
	if err != nil {
		panic(err)
	}

	tlsConf := tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"qproxy"},
	}

	listener, err := quic.ListenAddr(addr.String(), &tlsConf, &conf)
	if err != nil {
		panic(err)
	}

	var nextProxyConf *quic.ProxyConfig
	if nextProxyAddr != nil {
		nextProxyConf = &quic.ProxyConfig{
			Addr:    nextProxyAddr,
			RootCAs: common.NewCertPoolWithCert(tlsNextProxyCertFile),
		}
	}

	if serverSideInitialReceiveWindow > serverSideMaxReceiveWindow {
		serverSideMaxReceiveWindow = serverSideInitialReceiveWindow
	}

	p := &proxy{
		listener:                       listener,
		conf:                           conf,
		nextControlSessionId:           0,
		logger:                         common.DefaultLogger, //TODO cli option for prefix
		nextProxyConf:                  nextProxyConf,
		clientSideInitialReceiveWindow: clientSideInitialReceiveWindow,
		serverSideInitialReceiveWindow: serverSideInitialReceiveWindow,
		serverSideMaxReceiveWindow:     serverSideMaxReceiveWindow,
	}

	fmt.Printf("starting proxy with pid %d, port %d, cc cubic, iw %d\n", os.Getpid(), addr.Port, p.conf.InitialConnectionReceiveWindow)
	p.run()
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

	toServerConf := p.conf.Clone()
	if p.nextProxyConf != nil {
		toServerConf.Proxy = p.nextProxyConf
		toServerConf.EnableActiveMigration = true
		toServerConf.IgnoreReceived1RTTPacketsUntilFirstPathMigration = true
	}
	toServerConf.Tracer = tracer
	toServerState := state.Clone()
	if p.serverSideInitialReceiveWindow != 0 {
		toServerConf.InitialStreamReceiveWindow = p.serverSideInitialReceiveWindow
		toServerConf.InitialConnectionReceiveWindow = uint64(float64(p.serverSideInitialReceiveWindow) * quic.ConnectionFlowControlMultiplier)
		//TODO adjust transport parameters of state without destroying further handovers
	}
	if p.serverSideMaxReceiveWindow != 0 {
		toServerConf.MaxStreamReceiveWindow = p.serverSideMaxReceiveWindow
		toServerConf.MaxConnectionReceiveWindow = uint64(float64(p.serverSideMaxReceiveWindow) * quic.ConnectionFlowControlMultiplier)
	}
	sessionToServer, err := quic.RestoreSessionFromHandoverState(*toServerState, logging.PerspectiveClient, toServerConf, fmt.Sprintf("proxy_session %d (to server)", sessionID))
	if err != nil {
		return err
	}

	toClientConf := p.conf.Clone()
	toClientConf.Tracer = tracer
	toClientState := state.Clone()
	if p.clientSideInitialReceiveWindow != 0 {
		toClientState.ServerTransportParameters.InitialMaxStreamDataBidiLocal = quic.ByteCount(p.clientSideInitialReceiveWindow)
		toClientState.ServerTransportParameters.InitialMaxStreamDataBidiRemote = quic.ByteCount(p.clientSideInitialReceiveWindow)
		toClientState.ServerTransportParameters.InitialMaxStreamDataUni = quic.ByteCount(p.clientSideInitialReceiveWindow)
		toClientState.ServerTransportParameters.InitialMaxData = quic.ByteCount(float64(p.clientSideInitialReceiveWindow) * quic.ConnectionFlowControlMultiplier)
		toClientState.ClientTransportParameters.InitialMaxStreamDataBidiLocal = quic.ByteCount(p.clientSideInitialReceiveWindow)
		toClientState.ClientTransportParameters.InitialMaxStreamDataBidiRemote = quic.ByteCount(p.clientSideInitialReceiveWindow)
		toClientState.ClientTransportParameters.InitialMaxStreamDataUni = quic.ByteCount(p.clientSideInitialReceiveWindow)
		toClientState.ClientTransportParameters.InitialMaxData = quic.ByteCount(float64(p.clientSideInitialReceiveWindow) * quic.ConnectionFlowControlMultiplier)
		//TODO adjust transport parameters of state without destroying further handovers; further handovers currently do not work
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
