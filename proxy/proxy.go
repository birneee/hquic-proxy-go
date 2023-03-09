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
	"time"
)

type proxy struct {
	controlListener      quic.EarlyListener
	nextControlSessionId uint64
	nextProxySessionId   uint64
	config               *Config
}

var _ Proxy = &proxy{}

type RestoreConfig struct {
	OverwriteInitialReceiveWindow uint64
	MaxReceiveWindow              uint64
	InitialCongestionWindow       uint32
	MinCongestionWindow           uint32
	MaxCongestionWindow           uint32
	InitialSlowStartThreshold     quic.ByteCount
	MinSlowStartThreshold         quic.ByteCount
	MaxSlowStartThreshold         quic.ByteCount
	Tracer                        logging.Tracer
	// add a proxy on this connection after restore
	ProxyConf                      *quic.ProxyConfig
	HyblaWestwoodCongestionControl bool
	FixedPTO                       time.Duration
}

func populateRestoreConfig(config *RestoreConfig) *RestoreConfig {
	if config == nil {
		config = &RestoreConfig{}
	}
	if config.InitialCongestionWindow == 0 {
		config.InitialCongestionWindow = quic.DefaultInitialCongestionWindow
	}
	if config.MinCongestionWindow == 0 {
		config.MinCongestionWindow = quic.DefaultMinCongestionWindow
	}
	if config.MaxCongestionWindow == 0 {
		config.MaxCongestionWindow = quic.DefaultMaxCongestionWindow
	}
	if config.InitialSlowStartThreshold == 0 {
		config.InitialSlowStartThreshold = quic.DefaultInitialSlowStartThreshold
	}
	if config.MinSlowStartThreshold == 0 {
		config.MinSlowStartThreshold = quic.DefaultMinSlowStartThreshold
	}
	if config.MaxSlowStartThreshold == 0 {
		config.MaxSlowStartThreshold = quic.DefaultMaxSlowStartThreshold
	}

	return config
}

type Config struct {
	Logger                            common.Logger
	ControlConfig                     *ControlConfig
	ClientFacingProxyConnectionConfig *RestoreConfig
	ServerFacingProxyConnectionConfig *RestoreConfig
}

func populateConfig(config *Config) *Config {
	if config == nil {
		config = &Config{}
	}
	if config.Logger == nil {
		config.Logger = common.DefaultLogger.WithPrefix("proxy")
	}
	config.ControlConfig = populateControlConfig(config.ControlConfig, config.Logger.WithPrefix("control").Prefix())
	config.ClientFacingProxyConnectionConfig = populateRestoreConfig(config.ClientFacingProxyConnectionConfig)
	config.ServerFacingProxyConnectionConfig = populateRestoreConfig(config.ServerFacingProxyConnectionConfig)
	return config
}

type ControlConfig struct {
	Addr       net.Addr
	TlsConfig  *tls.Config
	QuicConfig *quic.Config
}

func populateControlConfig(config *ControlConfig, defaultLoggerPrefix string) *ControlConfig {
	if config == nil {
		config = &ControlConfig{}
	}
	if config.Addr == nil {
		config.Addr = &net.UDPAddr{IP: net.IPv4zero, Port: quic.DefaultHQUICProxyControlPort}
	}
	if config.TlsConfig == nil {
		config.TlsConfig = &tls.Config{}
	}
	if config.TlsConfig.NextProtos == nil || len(config.TlsConfig.NextProtos) == 0 {
		config.TlsConfig.NextProtos = []string{quic.HQUICProxyALPN}
	}
	if config.QuicConfig == nil {
		config.QuicConfig = &quic.Config{}
	}
	if config.QuicConfig.LoggerPrefix == "" {
		config.QuicConfig.LoggerPrefix = defaultLoggerPrefix
	}
	return config
}

// Run creates a H-QUIC proxy
func Run(config *Config) (Proxy, error) {
	config = populateConfig(config)

	controlListener, err := quic.ListenAddrEarly(config.ControlConfig.Addr.String(), config.ControlConfig.TlsConfig, config.ControlConfig.QuicConfig)
	if err != nil {
		return nil, err
	}

	p := &proxy{
		controlListener: controlListener,
		config:          config,
	}

	// print new reno as this is the only option in quic-go
	config.Logger.Infof("starting proxy with pid %d, port %d", os.Getpid(), config.ControlConfig.Addr.(*net.UDPAddr).Port)
	go p.run()

	return p, nil
}

func (p *proxy) acceptControlSession() (*controlSession, error) {
	quicConn, err := p.controlListener.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	controlSessionID := p.nextControlSessionId
	p.nextControlSessionId += 1
	return newControlSession(controlSessionID, quicConn, p.config.Logger.WithPrefix(fmt.Sprintf("control_session %d", controlSessionID))), nil
}

func (p *proxy) run() {
	for {
		controlSession, err := p.acceptControlSession()
		if err != nil {
			switch err.(type) {
			default:
				if err.Error() == "server closed" || err.Error() == "quic: Server closed" {
					// close gracefully
					return
				}
				panic(err)
			}
		}

		// use goroutine to not block other request while receiving H-QUIC state
		go func() {
			controlSession.logger.Infof("open")
			handoverState, err := controlSession.readHandoverStateAndClose()
			if err != nil {
				controlSession.logger.Errorf("failed to read handover state: %s", err)
				return
			}
			serverTP := handoverState.OwnTransportParameters(logging.PerspectiveServer)
			controlSession.logger.Infof("handover state received, odcid: %s", serverTP.OriginalDestinationConnectionID.String())
			controlSession.logger.Infof("closed")
			proxySessionID := p.nextProxySessionId
			p.nextProxySessionId += 1
			err = p.runProxySession(handoverState, proxySessionID, controlSession.quicConn.RemoteAddr().(*net.UDPAddr))
			if err != nil {
				controlSession.logger.Errorf("failed to run proxy session: %s", err)
				return
			}
		}()
	}
}

func (p *proxy) validateHandoverState(state *handover.State) error {
	clientTP := state.OwnTransportParameters(logging.PerspectiveClient)
	serverTP := state.OwnTransportParameters(logging.PerspectiveServer)

	if clientTP.ExtraStreamEncryption == true {
		return fmt.Errorf("XSE-QUIC extra_stream_encryption transport parameter must not be part of H-QUIC handover state")
	}
	if serverTP.ExtraStreamEncryption == true {
		return fmt.Errorf("XSE-QUIC extra_stream_encryption transport parameter must not be part of H-QUIC handover state")
	}
	return nil
}

func applyConfig(originalHandoverState *handover.State, pcc *RestoreConfig, tracer logging.Tracer) (*handover.State, *quic.Config) {
	conf := &quic.Config{}
	s := originalHandoverState.Clone()
	clientTP := s.OwnTransportParameters(logging.PerspectiveClient)
	serverTP := s.OwnTransportParameters(logging.PerspectiveServer)

	if pcc != nil {
		if pcc.ProxyConf != nil {
			conf.ProxyConf = pcc.ProxyConf.Clone()
		}
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
			serverTP.InitialMaxStreamDataBidiLocal = quic.ByteCount(pcc.OverwriteInitialReceiveWindow)
			serverTP.InitialMaxStreamDataBidiRemote = quic.ByteCount(pcc.OverwriteInitialReceiveWindow)
			serverTP.InitialMaxStreamDataUni = quic.ByteCount(pcc.OverwriteInitialReceiveWindow)
			serverTP.InitialMaxData = quic.ByteCount(float64(pcc.OverwriteInitialReceiveWindow) * quic.ConnectionFlowControlMultiplier)
			clientTP.InitialMaxStreamDataBidiLocal = quic.ByteCount(pcc.OverwriteInitialReceiveWindow)
			clientTP.InitialMaxStreamDataBidiRemote = quic.ByteCount(pcc.OverwriteInitialReceiveWindow)
			clientTP.InitialMaxStreamDataUni = quic.ByteCount(pcc.OverwriteInitialReceiveWindow)
			clientTP.InitialMaxData = quic.ByteCount(float64(pcc.OverwriteInitialReceiveWindow) * quic.ConnectionFlowControlMultiplier)
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
		if pcc.InitialSlowStartThreshold != 0 {
			conf.InitialSlowStartThreshold = pcc.InitialSlowStartThreshold
		}
		if pcc.MinSlowStartThreshold != 0 {
			conf.MinSlowStartThreshold = pcc.MinSlowStartThreshold
		}
		if pcc.MaxSlowStartThreshold != 0 {
			conf.MaxSlowStartThreshold = pcc.MaxSlowStartThreshold
		}

		conf.HyblaWestwoodCongestionControl = pcc.HyblaWestwoodCongestionControl
		conf.FixedPTO = pcc.FixedPTO

		if pcc.Tracer != nil {
			conf.Tracer = logging.NewMultiplexedTracer(tracer, pcc.Tracer)
		} else {
			conf.Tracer = tracer
		}
	}

	s.SetOwnTransportParameters(logging.PerspectiveClient, clientTP)
	s.SetOwnTransportParameters(logging.PerspectiveServer, serverTP)

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
			//TODO this does not work through NATs, client should multiplex connections
			state.ClientAddress = (&net.UDPAddr{IP: requesterAddr.IP, Port: clientAddr.Port}).String()
		}
	}

	logger := p.config.Logger.WithPrefix(fmt.Sprintf("proxy_session %d", sessionID))

	proxySession := proxySession{
		sessionID:          sessionID,
		logger:             logger,
		clientFacingLogger: logger.WithPrefix("client_facing"),
		serverFacingLogger: logger.WithPrefix("server_facing"),
	}

	connectionTracer := common.NewEventTracer(common.Handlers{
		UpdatePath: func(odcid logging.ConnectionID, newRemote net.Addr) {
			logger.Debugf("migrated QUIC connection %s to %s", odcid.String(), newRemote)
		},
		StartedConnection: func(odcid logging.ConnectionID, local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
			logger.Debugf("started QUIC connection %s", odcid.String())
		},
		ClosedConnection: func(odcid logging.ConnectionID, err error) {
			logger.Debugf("closed QUIC connection %s", odcid.String())
		},
	})

	handshakeDoneFrameTracer := common.NewFrameTracer[logging.HandshakeDoneFrame](func() {
		proxySession.onServerFacingConnectionReceiveHandshakeDoneFrame()
	})

	clientFacingHandoverState, clientFacingConfig := applyConfig(state, p.config.ClientFacingProxyConnectionConfig, connectionTracer)
	clientFacingConfig.LoggerPrefix = fmt.Sprintf("proxy_session %d (client facing)", sessionID)
	var clientFacingBidiStreams map[quic.StreamID]quic.Stream
	proxySession.clientFacingConn, clientFacingBidiStreams, _, _, err = quic.Restore(*clientFacingHandoverState, quic.PerspectiveServer, clientFacingConfig)
	if err != nil {
		return err
	}

	// restore server-facing after client-facing connection so client-facing connection is available for HANDOVER_DONE forwarding
	serverFacingHandoverState, serverFacingConfig := applyConfig(state, p.config.ServerFacingProxyConnectionConfig, logging.NewMultiplexedTracer(connectionTracer, handshakeDoneFrameTracer))
	serverFacingConfig.LoggerPrefix = fmt.Sprintf("proxy_session %d (server facing)", sessionID)
	var serverFacingBidiStreams map[quic.StreamID]quic.Stream
	proxySession.serverFacingConn, serverFacingBidiStreams, _, _, err = quic.Restore(*serverFacingHandoverState, quic.PerspectiveClient, serverFacingConfig)
	if err != nil {
		return err
	}

	err = proxySession.connectAllStreams(clientFacingBidiStreams, serverFacingBidiStreams)
	if err != nil {
		return err
	}

	go proxySession.run()
	return nil
}

func (p *proxy) Addr() net.Addr {
	return p.controlListener.Addr()
}

func (p *proxy) Close() error {
	return p.controlListener.Close()
}
