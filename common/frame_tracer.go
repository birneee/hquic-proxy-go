package common

import (
	"context"
	"github.com/lucas-clemente/quic-go/logging"
)

type frameTracer[T logging.Frame] struct {
	logging.NullTracer
	onFrame func()
}

func NewFrameTracer[T logging.Frame](onFrame func()) logging.Tracer {
	return &frameTracer[T]{
		onFrame: onFrame,
	}
}

func (t *frameTracer[T]) TracerForConnection(ctx context.Context, p logging.Perspective, odcid logging.ConnectionID) logging.ConnectionTracer {
	return &frameConnectionTracer[T]{
		onFrame: t.onFrame,
	}
}

type frameConnectionTracer[T logging.Frame] struct {
	logging.NullConnectionTracer
	onFrame func()
}

func (ct *frameConnectionTracer[T]) ReceivedLongHeaderPacket(_ *logging.ExtendedHeader, _ logging.ByteCount, frames []logging.Frame) {
	for _, frame := range frames {
		ct.handleFrame(frame)
	}
}

func (ct *frameConnectionTracer[T]) ReceivedShortHeaderPacket(_ *logging.ShortHeader, _ logging.ByteCount, frames []logging.Frame) {
	for _, frame := range frames {
		ct.handleFrame(frame)
	}
}

func (ct *frameConnectionTracer[T]) handleFrame(frame logging.Frame) {
	switch frame.(type) {
	case T, *T:
		ct.onFrame()
	}
}
