package proxy

import (
	"context"
	"encoding/json"
	"github.com/birneee/hquic-proxy-go/common"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/handover"
	"io"
)

type controlSession struct {
	sessionID   uint64
	quicSession quic.Session
	logger      common.Logger
}

func newControlSession(sessionID uint64, quicSession quic.Session, logger common.Logger) *controlSession {
	return &controlSession{sessionID: sessionID, quicSession: quicSession, logger: logger}
}

func (s *controlSession) readHandoverStateAndClose() (*handover.State, error) {
	stream, err := s.quicSession.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}

	marshalledState, err := io.ReadAll(stream)
	if err != nil {
		return nil, err
	}

	s.logger.Debugf("received handover state %s", string(marshalledState))

	state := &handover.State{}
	err = json.Unmarshal(marshalledState, state)
	if err != nil {
		return nil, err
	}
	_ = s.quicSession.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "handover_state_received")

	return state, nil
}
