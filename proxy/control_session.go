package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/birneee/hquic-proxy-go/common"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/handover"
	"io"
)

type controlSession struct {
	sessionID uint64
	quicConn  quic.Connection
	logger    common.Logger
}

func newControlSession(sessionID uint64, quicConn quic.Connection, logger common.Logger) *controlSession {
	return &controlSession{sessionID: sessionID, quicConn: quicConn, logger: logger}
}

func (s *controlSession) readHandoverStateAndClose() (*handover.State, error) {
	stream, err := s.quicConn.AcceptStream(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to accept stream: %w", err)
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
	_ = s.quicConn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "handover_state_received")

	return state, nil
}
