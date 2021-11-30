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
	listener             quic.Listener
	conf                 quic.Config
	nextControlSessionId uint64
	nextProxySessionId   uint64
	logger               common.Logger
}

func RunProxy(addr net.UDPAddr, tlsProxyCertFile string, tlsProxyKeyFile string) {
	p := newProxy(addr, tlsProxyCertFile, tlsProxyKeyFile)
	fmt.Printf("starting proxy with pid %d, port %d, cc cubic, iw %d\n", os.Getpid(), addr.Port, p.conf.InitialConnectionReceiveWindow)
	p.run()
}

func newProxy(addr net.UDPAddr, tlsProxyCertFile string, tlsProxyKeyFile string) *proxy {
	//TODO make cli options
	conf := quic.Config{
		InitialConnectionReceiveWindow: 2_000_000,
		MaxStreamReceiveWindow:         200_000_000,
		InitialStreamReceiveWindow:     2_000_000,
		MaxConnectionReceiveWindow:     200_000_000,
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

	return &proxy{listener: listener, conf: conf, nextControlSessionId: 0, logger: common.DefaultLogger.WithPrefix("proxy")}
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
		err = p.runProxySession(handoverState, proxySessionID)
		if err != nil {
			controlSession.logger.Errorf("failed to run proxy session: %s", err)
			continue
		}
	}
}

func (p *proxy) runProxySession(state *handover.State, sessionID uint64) error {
	sessionToServer, err := quic.RestoreSessionFromHandoverState(*state, logging.PerspectiveClient, &p.conf, fmt.Sprintf("proxy_session %d (to server)", sessionID))
	if err != nil {
		return err
	}

	sessionToClient, err := quic.RestoreSessionFromHandoverState(*state, logging.PerspectiveServer, &p.conf, fmt.Sprintf("proxy_session %d (to client)", sessionID))
	if err != nil {
		return err
	}

	proxySession := proxySession{
		sessionID:           sessionID,
		quicSessionToServer: sessionToServer,
		quicSessionToClient: sessionToClient,
		logger:              p.logger.WithPrefix(fmt.Sprintf("proxy_session %d", sessionID)),
	}

	go proxySession.run()
	return nil
}
