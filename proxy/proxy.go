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
	listener             quic.EarlyListener
	nextControlSessionId uint64
	nextProxySessionId   uint64
	logger               common.Logger
	clientSideConf       *RestoreConfig
	serverSideConf       *RestoreConfig
}

var _ Proxy = &proxy{}

type RestoreConfig struct {
	OverwriteInitialReceiveWindow uint64
	MaxReceiveWindow              uint64
	InitialCongestionWindow       uint32
	MinCongestionWindow           uint32
	MaxCongestionWindow           uint32
	Tracer                        logging.Tracer
	// add a proxy on this connection after restore
	ProxyConf *quic.ProxyConfig
}

type ProxyConfig struct {
	ClientFacingProxyConnectionConfig *RestoreConfig
	ServerFacingProxyConnectionConfig *RestoreConfig
}

// ListenAddr creates a H-QUIC proxy listening on a given address.
func ListenAddr(addr string, tlsConfig *tls.Config, config *quic.Config, proxyConfig *ProxyConfig) (Proxy, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	var clientFacingProxyConnectionConfig *RestoreConfig
	var serverFacingProxyConnectionConfig *RestoreConfig
	if proxyConfig != nil {
		clientFacingProxyConnectionConfig = proxyConfig.ClientFacingProxyConnectionConfig
		serverFacingProxyConnectionConfig = proxyConfig.ServerFacingProxyConnectionConfig
	}

	return RunProxy(*udpAddr, tlsConfig, config, clientFacingProxyConnectionConfig, serverFacingProxyConnectionConfig)
}

func RunProxy(addr net.UDPAddr, controlTlsConfig *tls.Config, controlConfig *quic.Config, clientSideConf *RestoreConfig, serverSideConf *RestoreConfig) (Proxy, error) {

	if len(controlTlsConfig.NextProtos) == 0 {
		controlTlsConfig.NextProtos = []string{HQUICProxyALPN}
	}

	listener, err := quic.ListenAddrEarly(addr.String(), controlTlsConfig, controlConfig)
	if err != nil {
		return nil, err
	}

	logger := common.DefaultLogger.WithPrefix(controlConfig.LoggerPrefix)

	p := &proxy{
		listener:             listener,
		nextControlSessionId: 0,
		logger:               logger,
		clientSideConf:       clientSideConf,
		serverSideConf:       serverSideConf,
	}

	// print new reno as this is the only option in quic-go
	logger.Infof("starting proxy with pid %d, port %d, cc new reno", os.Getpid(), addr.Port)
	go p.run()

	return p, nil
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
			switch err.(type) {
			default:
				if err.Error() == "server closed" {
					// close gracefully
					return
				}
				panic(err)
			}
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

func (p *proxy) validateHandoverState(state *handover.State) error {
	if state.ClientTransportParameters.ExtraStreamEncryption == true {
		return fmt.Errorf("XSE-QUIC extra_stream_encryption transport parameter must not be part of H-QUIC handover state")
	}
	if state.ServerTransportParameters.ExtraStreamEncryption == true {
		return fmt.Errorf("XSE-QUIC extra_stream_encryption transport parameter must not be part of H-QUIC handover state")
	}
	return nil
}

func applyConfig(originalHandoverState *handover.State, pcc *RestoreConfig, tracer logging.Tracer) (*handover.State, *quic.Config) {
	conf := &quic.Config{}
	s := originalHandoverState.Clone()

	if pcc != nil {
		conf.ProxyConf = pcc.ProxyConf
		if conf.ProxyConf != nil {
			conf.EnableActiveMigration = true
			conf.IgnoreReceived1RTTPacketsUntilFirstPathMigration = true
			if conf.ProxyConf.ModifyState != nil {
				panic("not supported yet")
			}
			conf.ProxyConf.ModifyState = func(state *handover.State) {
				// use original transport parameters because they might have changed because of proxy optimizations
				state.ClientTransportParameters = originalHandoverState.ClientTransportParameters
				state.ServerTransportParameters = originalHandoverState.ServerTransportParameters
			}
		}

		if pcc.OverwriteInitialReceiveWindow != 0 {
			conf.InitialStreamReceiveWindow = pcc.OverwriteInitialReceiveWindow
			conf.InitialConnectionReceiveWindow = uint64(float64(pcc.OverwriteInitialReceiveWindow) * quic.ConnectionFlowControlMultiplier)
			s.ServerTransportParameters.InitialMaxStreamDataBidiLocal = quic.ByteCount(pcc.OverwriteInitialReceiveWindow)
			s.ServerTransportParameters.InitialMaxStreamDataBidiRemote = quic.ByteCount(pcc.OverwriteInitialReceiveWindow)
			s.ServerTransportParameters.InitialMaxStreamDataUni = quic.ByteCount(pcc.OverwriteInitialReceiveWindow)
			s.ServerTransportParameters.InitialMaxData = quic.ByteCount(float64(pcc.OverwriteInitialReceiveWindow) * quic.ConnectionFlowControlMultiplier)
			s.ClientTransportParameters.InitialMaxStreamDataBidiLocal = quic.ByteCount(pcc.OverwriteInitialReceiveWindow)
			s.ClientTransportParameters.InitialMaxStreamDataBidiRemote = quic.ByteCount(pcc.OverwriteInitialReceiveWindow)
			s.ClientTransportParameters.InitialMaxStreamDataUni = quic.ByteCount(pcc.OverwriteInitialReceiveWindow)
			s.ClientTransportParameters.InitialMaxData = quic.ByteCount(float64(pcc.OverwriteInitialReceiveWindow) * quic.ConnectionFlowControlMultiplier)
		}
		if pcc.MaxReceiveWindow != 0 {
			conf.MaxStreamReceiveWindow = pcc.MaxReceiveWindow
			conf.MaxConnectionReceiveWindow = uint64(float64(pcc.MaxReceiveWindow) * quic.ConnectionFlowControlMultiplier)
		}
		if pcc.InitialCongestionWindow != 0 {
			conf.InitialCongestionWindow = pcc.InitialCongestionWindow
		}
		if pcc.MinCongestionWindow != 0 {
			conf.MinCongestionWindow = pcc.MinCongestionWindow
		}
		if pcc.MaxCongestionWindow != 0 {
			conf.MaxCongestionWindow = pcc.MaxCongestionWindow
		}
		if pcc.Tracer != nil {
			conf.Tracer = logging.NewMultiplexedTracer(tracer, pcc.Tracer)
		} else {
			conf.Tracer = tracer
		}
	}

	return s, conf
}

func (p *proxy) runProxySession(state *handover.State, sessionID uint64, requesterAddr *net.UDPAddr) error {
	err := p.validateHandoverState(state)
	if err != nil {
		return err
	}

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

	serverFacingHandoverState, serverFacingConfig := applyConfig(state, p.serverSideConf, tracer)
	serverFacingConfig.LoggerPrefix = fmt.Sprintf("proxy_session %d (server facing)", sessionID)
	serverFacingSession, err := quic.Restore(*serverFacingHandoverState, quic.PerspectiveClient, serverFacingConfig)
	if err != nil {
		return err
	}

	clientFacingHandoverState, clientFacingConfig := applyConfig(state, p.clientSideConf, tracer)
	clientFacingConfig.LoggerPrefix = fmt.Sprintf("proxy_session %d (client facing)", sessionID)
	clientFacingSession, err := quic.Restore(*clientFacingHandoverState, quic.PerspectiveServer, clientFacingConfig)
	if err != nil {
		return err
	}

	proxySession := proxySession{
		sessionID:           sessionID,
		quicSessionToServer: serverFacingSession,
		quicSessionToClient: clientFacingSession,
		logger:              logger,
	}

	go proxySession.run()
	return nil
}

func (p *proxy) Addr() net.Addr {
	return p.listener.Addr()
}

func (p *proxy) Close() error {
	return p.listener.Close()
}
