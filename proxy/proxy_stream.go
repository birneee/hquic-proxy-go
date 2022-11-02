package proxy

import (
	"github.com/birneee/hquic-proxy-go/common"
	"github.com/lucas-clemente/quic-go"
	"io"
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

func (s *proxyStream) forward(dst quic.SendStream, src quic.ReceiveStream) {
	eof := false
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
				s.proxySession.handleApplicationError(s.connectionOf(src), err)
				s.handleClose()
				return
			default:
				if err == io.EOF {
					// close one direction of stream
					eof = true
				} else {
					s.logger.Errorf("%s", err)
					s.handleClose()
					return
				}
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
				s.proxySession.handleApplicationError(s.connectionOf(dst), err)
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

		if eof {
			err = dst.Close()
			if err != nil {
				s.logger.Errorf("failed to close stream: %s", err)
			}
			return
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

func (s *proxyStream) connectionOf(stream interface{}) quic.Connection {
	if stream == s.streamToClient {
		return s.proxySession.quicConnToClient
	} else {
		return s.proxySession.quicConnToServer
	}
}
