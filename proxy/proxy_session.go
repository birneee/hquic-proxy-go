package proxy

import (
	"context"
	"fmt"
	"github.com/birneee/hquic-proxy-go/common"
	"github.com/lucas-clemente/quic-go"
	"sync"
)

type proxySession struct {
	sessionID                     uint64
	clientFacingConn              quic.Connection
	serverFacingConn              quic.Connection
	logger                        common.Logger
	clientFacingLogger            common.Logger
	serverFacingLogger            common.Logger
	closeOnce                     sync.Once
	forwardHandshakeDoneFrameOnce sync.Once
}

func (s *proxySession) run() {
	s.logger.Infof("open")
	go s.handleOpenedStreams(s.clientFacingConn, s.serverFacingConn)
	go s.handleOpenedStreams(s.serverFacingConn, s.clientFacingConn)
}

// handle streams opened by the conn1
// request is forwarded to conn2
func (s *proxySession) handleOpenedStreams(conn1 quic.Connection, conn2 quic.Connection) {
	for {
		stream1, err := conn1.AcceptStream(context.Background())
		if err != nil {
			s.handleError(conn1, err)
			return
		}
		stream2, err := conn2.OpenStream()
		if err != nil {
			s.handleError(conn2, err)
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

		if conn1 == s.clientFacingConn {
			ps.streamToClient = stream1
			ps.streamToServer = stream2
		} else {
			ps.streamToServer = stream1
			ps.streamToClient = stream2
		}

		ps.run()
	}
}

func (s *proxySession) handleError(from quic.Connection, err error) {
	switch err := err.(type) {
	case *quic.TransportError:
		s.getConnectionLogger(from).Infof("transport error: %v", err)
		s.closeOnce.Do(func() {
			s.logger.Infof("close")
		})
	case *quic.ApplicationError:
		s.getConnectionLogger(from).Debugf("application error: %v", err)
		s.closeOnce.Do(func() {
			if err.Remote {
				s.getConnectionLogger(s.otherConnection(from)).Debugf("forward error: %s", err)
				_ = s.otherConnection(from).CloseWithError(err.ErrorCode, err.ErrorMessage)
			}
			s.logger.Infof("close")
		})
	case *quic.VersionNegotiationError:
		s.getConnectionLogger(from).Infof("version negotiation error: %v", err)
		s.closeOnce.Do(func() {
			s.logger.Infof("close")
		})
	case *quic.StatelessResetError:
		s.getConnectionLogger(from).Infof("stateless reset error: %v", err)
		s.closeOnce.Do(func() {
			s.logger.Infof("close")
		})
	case *quic.IdleTimeoutError:
		s.getConnectionLogger(from).Infof("idle timeout error: %v", err)
		s.closeOnce.Do(func() {
			s.logger.Infof("close")
		})
	case *quic.HandshakeTimeoutError:
		s.getConnectionLogger(from).Infof("handshake timeout error: %v", err)
		s.closeOnce.Do(func() {
			s.logger.Infof("close")
		})
	default:
		s.getConnectionLogger(from).Infof("unknown error: %v", err)
		s.closeOnce.Do(func() {
			//TODO make Transport Error instead of Application Error
			_ = s.otherConnection(from).CloseWithError(quic.ApplicationErrorCode(quic.InternalError), "error on other proxy quic connection")
			s.logger.Infof("close")
		})
	}

}

func (s *proxySession) getConnectionLogger(conn quic.Connection) common.Logger {
	switch conn {
	case s.clientFacingConn:
		return s.clientFacingLogger
	case s.serverFacingConn:
		return s.serverFacingLogger
	}
	panic("unknown connection")
}

func (s *proxySession) otherConnection(conn quic.Connection) quic.Connection {
	switch conn {
	case s.clientFacingConn:
		return s.serverFacingConn
	case s.serverFacingConn:
		return s.clientFacingConn
	}
	panic("unknown connection")
}

func (s *proxySession) onServerFacingConnectionReceiveHandshakeDoneFrame() {
	s.forwardHandshakeDoneFrameOnce.Do(func() {
		s.logger.Debugf("forward HANDSHAKE_DONE frame")
		err := s.clientFacingConn.QueueHandshakeDoneFrame()
		if err != nil {
			panic(err)
		}
	})
}
