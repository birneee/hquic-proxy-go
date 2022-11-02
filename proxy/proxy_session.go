package proxy

import (
	"context"
	"fmt"
	"github.com/birneee/hquic-proxy-go/common"
	"github.com/lucas-clemente/quic-go"
	"sync"
)

type proxySession struct {
	sessionID        uint64
	quicConnToClient quic.Connection
	quicConnToServer quic.Connection
	logger           common.Logger
	closeOnce        sync.Once
}

func (s *proxySession) run() {
	s.logger.Infof("open")
	go s.handleOpenedStreams(s.quicConnToClient, s.quicConnToServer)
	go s.handleOpenedStreams(s.quicConnToServer, s.quicConnToClient)
}

// handle streams opened by the conn1
// request is forwarded to conn2
func (s *proxySession) handleOpenedStreams(conn1 quic.Connection, conn2 quic.Connection) {
	for {
		stream1, err := conn1.AcceptStream(context.Background())
		if err != nil {
			switch err := err.(type) {
			case *quic.ApplicationError:
				s.handleApplicationError(conn1, err)
			default:
				s.logger.Errorf(err.Error())
				//TODO make Transport Error instead of Application Error
				_ = conn2.CloseWithError(quic.ApplicationErrorCode(quic.InternalError), "error on other proxy connection")
			}
			s.handleClose()
			return
		}
		stream2, err := conn2.OpenStream()
		if err != nil {
			switch err := err.(type) {
			case *quic.ApplicationError:
				s.handleApplicationError(conn2, err)
			default:
				s.logger.Errorf(err.Error())
				//TODO make Transport Error instead of Application Error
				_ = conn1.CloseWithError(quic.ApplicationErrorCode(quic.InternalError), "error on other proxy quic connection")
			}
			s.handleClose()
			return
		}
		if stream1.StreamID() != stream2.StreamID() {
			panic("stream IDs do not match")
		}

		ps := proxyStream{
			proxySession: s,
			streamID:     stream1.StreamID(),
			logger:       s.logger.WithPrefix(fmt.Sprintf("stream %d", stream1.StreamID())),
		}

		if conn1 == s.quicConnToClient {
			ps.streamToClient = stream1
			ps.streamToServer = stream2
		} else {
			ps.streamToServer = stream1
			ps.streamToClient = stream2
		}

		ps.run()
	}
}

func (s *proxySession) handleApplicationError(from quic.Connection, err *quic.ApplicationError) {
	s.closeOnce.Do(func() {
		if err.Remote {
			s.logger.Debugf("forward error: %s", err)
			_ = s.otherConnection(from).CloseWithError(err.ErrorCode, err.ErrorMessage)
		}
		s.logger.Infof("close")
	})
}

func (s *proxySession) otherConnection(conn quic.Connection) quic.Connection {
	switch conn {
	case s.quicConnToClient:
		return s.quicConnToServer
	case s.quicConnToServer:
		return s.quicConnToClient
	}
	panic("unknown connection")
}

func (s *proxySession) handleClose() {
	s.closeOnce.Do(func() {
		s.logger.Infof("close")
	})
}
