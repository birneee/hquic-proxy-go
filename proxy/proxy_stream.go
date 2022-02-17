package proxy

import (
	"github.com/birneee/hquic-proxy-go/common"
	"github.com/lucas-clemente/quic-go"
	"sync"
)

type proxyStream struct {
	proxySession   *proxySession
	streamID       quic.StreamID
	streamToClient quic.Stream
	streamToServer quic.Stream
	logger         common.Logger
	closeOnce      sync.Once
}

func (s *proxyStream) forward(dst quic.Stream, src quic.Stream) {
	buf := make([]byte, 1e6)
	for {
		nr, err := src.Read(buf)
		if err != nil {
			switch err := err.(type) {
			case *quic.StreamError:
				// src endpoint sent CancelWrite
				// forward to dst endpoint
				dst.CancelWrite(err.ErrorCode)
				return
			case *quic.ApplicationError:
				s.proxySession.handleApplicationError(s.sessionOf(src), err)
				s.handleClose()
				return
			default:
				s.logger.Errorf("%s", err)
				s.handleClose()
				return
			}
		}

		nw, err := dst.Write(buf[0:nr])
		if err != nil {
			switch err := err.(type) {
			case *quic.StreamError:
				// dst endpoint sent CancelRead
				// forward to src endpoint
				src.CancelRead(err.ErrorCode)
				return
			case *quic.ApplicationError:
				s.proxySession.handleApplicationError(s.sessionOf(dst), err)
				s.handleClose()
				return
			default:
				s.logger.Errorf("%s", err)
				s.handleClose()
				return
			}
		}

		if nr != nw {
			panic("short write error")
		}
	}
}

func (s *proxyStream) run() {
	s.logger.Infof("open")
	go s.forward(s.streamToClient, s.streamToServer)
	go s.forward(s.streamToServer, s.streamToClient)
}

func (s *proxyStream) handleClose() {
	s.closeOnce.Do(func() {
		s.logger.Infof("close")
	})
}

func (s *proxyStream) sessionOf(stream quic.Stream) quic.Session {
	if stream == s.streamToClient {
		return s.proxySession.quicSessionToClient
	} else {
		return s.proxySession.quicSessionToServer
	}
}
