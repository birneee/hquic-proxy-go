package common

import (
	"context"
	"crypto/tls"
	"github.com/birneee/hquic-proxy-go/internal/testdata"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/logging"
	"net"
	"testing"
	"time"
)

var clientConfig = &quic.Config{
	EnableActiveMigration: true,
	MaxIdleTimeout:        time.Second,
}

var serverConfig = &quic.Config{
	EnableActiveMigration: true,
	MaxIdleTimeout:        time.Second,
}

var clientTlsConfig = &tls.Config{
	InsecureSkipVerify: true,
	NextProtos:         []string{"test"},
}

var serverTlsConfig = &tls.Config{
	Certificates: testdata.GetTLSConfig().Certificates,
	NextProtos:   []string{"test"},
}

func TestObserveFrame(t *testing.T) {
	testCtx, testCtxChancel := context.WithTimeout(context.Background(), time.Second)
	defer testCtxChancel()
	serverAddrChan := make(chan net.Addr, 1)
	rcvChan := make(chan struct{})
	// run server
	go func() {
		server, err := quic.ListenAddr("127.0.0.1:0", serverTlsConfig, serverConfig)
		if err != nil {
			t.Error(err)
		}
		defer server.Close()
		serverAddrChan <- server.Addr()
		_, err = server.Accept(testCtx)
		if err != nil {
			t.Errorf(err.Error())
		}
	}()
	//run client
	go func() {
		serverAddr := <-serverAddrChan
		clientConfig := clientConfig.Clone()
		clientConfig.Tracer = NewFrameTracer[logging.HandshakeDoneFrame](func() {
			rcvChan <- struct{}{}
		})
		_, err := quic.DialAddr(serverAddr.String(), clientTlsConfig, clientConfig)
		if err != nil {
			t.Error(err)
		}
	}()

	select {
	case <-rcvChan:
		// success
	case <-testCtx.Done():
		t.Error("timeout")
	}
}
