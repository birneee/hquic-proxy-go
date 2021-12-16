package proxy

import (
	"context"
	"fmt"
	"github.com/birneee/hquic-proxy-go/common"
	"github.com/lucas-clemente/quic-go"
	"sync"
)

type proxySession struct {
	sessionID           uint64
	quicSessionToClient quic.Session
	quicSessionToServer quic.Session
	logger              common.Logger
	closeOnce           sync.Once
}

func (s *proxySession) run() {
	s.logger.Infof("open")
	go s.handleOpenedStreams(s.quicSessionToClient, s.quicSessionToServer)
	go s.handleOpenedStreams(s.quicSessionToServer, s.quicSessionToClient)
}

// handle streams opened by the session1
// request is forwarded to session2
func (s *proxySession) handleOpenedStreams(session1 quic.Session, session2 quic.Session) {
	for {
		stream1, err := session1.AcceptStream(context.Background())
		if err != nil {
			switch err := err.(type) {
			case *quic.ApplicationError:
				s.handleApplicationError(session1, err)
			default:
				//s.logger.Errorf(reflect.TypeOf(err).String())
				s.logger.Errorf(err.Error())
				//TODO make Transport Error instead of Application Error
				_ = session2.CloseWithError(quic.ApplicationErrorCode(quic.InternalError), "error on other proxy session")
			}
			s.handleClose()
			return
		}
		stream2, err := session2.OpenStream()
		if err != nil {
			switch err := err.(type) {
			case *quic.ApplicationError:
				s.handleApplicationError(session2, err)
			default:
				//s.logger.Errorf(reflect.TypeOf(err).String())
				s.logger.Errorf(err.Error())
				//TODO make Transport Error instead of Application Error
				_ = session1.CloseWithError(quic.ApplicationErrorCode(quic.InternalError), "error on other proxy quic session")
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

		if session1 == s.quicSessionToClient {
			ps.streamToClient = stream1
			ps.streamToServer = stream2
		} else {
			ps.streamToServer = stream1
			ps.streamToClient = stream2
		}

		ps.run()
	}
}

func (s *proxySession) handleApplicationError(from quic.Session, err *quic.ApplicationError) {
	s.closeOnce.Do(func() {
		if err.Remote {
			s.logger.Debugf("forward error: %s", err)
			_ = s.otherSession(from).CloseWithError(err.ErrorCode, err.ErrorMessage)
		}
		s.logger.Infof("close")
	})
}

func (s *proxySession) otherSession(session quic.Session) quic.Session {
	switch session {
	case s.quicSessionToClient:
		return s.quicSessionToServer
	case s.quicSessionToServer:
		return s.quicSessionToClient
	}
	panic("unknown session")
}

func (s *proxySession) handleClose() {
	s.closeOnce.Do(func() {
		s.logger.Infof("close")
	})
}
