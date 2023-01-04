package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/birneee/hquic-proxy-go/common"
	"github.com/birneee/hquic-proxy-go/internal/testdata"
	"github.com/lucas-clemente/quic-go"
	"net"
	"reflect"
	"testing"
	"time"
)

func transmitMessages(from quic.Connection, to quic.Connection) error {
	writer, err := from.OpenStream()
	if err != nil {
		return err
	}
	if from.RemoteAddr().(*net.UDPAddr).Port == to.LocalAddr().(*net.UDPAddr).Port {
		return fmt.Errorf("did not migrate before opening stream")
	}
	writeBuf := []byte("hello")
	_, err = writer.Write(writeBuf)
	if err != nil {
		return err
	}
	reader, err := to.AcceptStream(context.Background())
	if err != nil {
		return err
	}
	readBuf := make([]byte, len(writeBuf))
	_, err = reader.Read(readBuf)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(writeBuf, readBuf) {
		return fmt.Errorf("failed to transmit message")
	}
	return nil
}

const message string = "hello"

var clientConfig = &quic.Config{
	EnableActiveMigration: true,
	MaxIdleTimeout:        time.Second,
}

var serverConfig = &quic.Config{
	EnableActiveMigration: true,
	MaxIdleTimeout:        time.Second,
}

var proxyControlTlsConfig = &tls.Config{
	InsecureSkipVerify: true,
	NextProtos:         []string{quic.HQUICProxyALPN},
}

var clientTlsConfig = &tls.Config{
	InsecureSkipVerify: true,
	NextProtos:         []string{"test"},
}

var serverTlsConfig = &tls.Config{
	Certificates: testdata.GetTLSConfig().Certificates,
	NextProtos:   []string{"test"},
}

var proxyTlsConfig = &tls.Config{
	Certificates: testdata.GetTLSConfig().Certificates,
}

func TestOneProxy(t *testing.T) {
	testOneProxy(t, false)
}

func TestEarlyHandoverOneProxy(t *testing.T) {
	testOneProxy(t, true)
}

func testOneProxy(t *testing.T, allowEarlyHandover bool) {
	serverContext, serverContextCancel := context.WithCancel(context.Background())
	serverAddrChan := make(chan net.Addr, 1)
	go func() {
		server, err := quic.ListenAddr("127.0.0.1:0", serverTlsConfig, serverConfig)
		if err != nil {
			t.Errorf(err.Error())
		}
		defer server.Close()
		serverAddrChan <- server.Addr()
		serverConn, err := server.Accept(context.Background())
		if err != nil {
			t.Errorf(err.Error())
		}
		err = acceptAndReceive(serverConn, message)
		if err != nil {
			t.Errorf(err.Error())
		}
		err = openAndSend(serverConn, message)
		if err != nil {
			t.Errorf(err.Error())
		}
		<-serverConn.Context().Done()
		serverContextCancel()
	}()

	proxyContext, proxyContextCancel := context.WithCancel(context.Background())
	proxyAddrChan := make(chan net.Addr, 1)
	go func() {
		proxy, err := Run(&Config{
			ControlConfig: &ControlConfig{
				Addr:      &net.UDPAddr{IP: common.IPv4loopback, Port: 0},
				TlsConfig: proxyTlsConfig,
			},
		})
		if err != nil {
			t.Errorf(err.Error())
		}
		proxyAddrChan <- proxy.Addr()
		<-serverContext.Done()
		proxyContextCancel()
	}()

	proxyAddr := <-proxyAddrChan
	clientConfig := clientConfig.Clone()
	clientConfig.AllowEarlyHandover = allowEarlyHandover
	clientConfig.ProxyConf = &quic.ProxyConfig{
		Addr:    proxyAddr.String(),
		TlsConf: proxyControlTlsConfig,
	}

	serverAddr := <-serverAddrChan
	client, err := quic.DialAddr(serverAddr.String(), clientTlsConfig, clientConfig)
	if err != nil {
		t.Errorf(err.Error())
	}

	err = openAndSend(client, message)
	if err != nil {
		t.Errorf(err.Error())
	}
	err = acceptAndReceive(client, message)
	if err != nil {
		t.Errorf(err.Error())
	}

	<-serverContext.Done()
	<-proxyContext.Done()
}

func TestTwoProxy(t *testing.T) {
	proxy2, err := Run(&Config{
		ControlConfig: &ControlConfig{
			Addr:      &net.UDPAddr{IP: common.IPv4loopback, Port: 0},
			TlsConfig: proxyTlsConfig,
			QuicConfig: &quic.Config{
				LoggerPrefix: "proxy2",
			},
		},
	})
	if err != nil {
		t.Errorf(err.Error())
	}
	proxy1, err := Run(&Config{
		ControlConfig: &ControlConfig{
			Addr:      &net.UDPAddr{IP: common.IPv4loopback, Port: 0},
			TlsConfig: proxyTlsConfig,
			QuicConfig: &quic.Config{
				LoggerPrefix: "proxy1",
			},
		},
		ServerFacingProxyConnectionConfig: &RestoreConfig{
			ProxyConf: &quic.ProxyConfig{
				Addr:    proxy2.Addr().String(),
				TlsConf: clientTlsConfig,
			},
		},
	})
	if err != nil {
		t.Errorf(err.Error())
	}
	server, err := quic.ListenAddr("127.0.0.1:0", serverTlsConfig, serverConfig)
	if err != nil {
		t.Errorf(err.Error())
	}
	clientConfig := clientConfig.Clone()
	clientConfig.ProxyConf = &quic.ProxyConfig{
		Addr:    proxy1.Addr().String(),
		TlsConf: clientTlsConfig,
	}
	client, err := quic.DialAddr(server.Addr().String(), clientTlsConfig, clientConfig)
	if err != nil {
		t.Errorf(err.Error())
	}
	serverConn, err := server.Accept(context.Background())
	if err != nil {
		t.Errorf(err.Error())
	}
	err = transmitMessages(client, serverConn)
	if err != nil {
		t.Errorf(err.Error())
	}
	err = transmitMessages(serverConn, client)
	if err != nil {
		t.Errorf(err.Error())
	}
	err = server.Close()
	if err != nil {
		t.Errorf(err.Error())
	}
}

func receiveMessage(stream quic.Stream, msg string) error {
	buf := make([]byte, 2*len(msg))
	n, err := stream.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != msg {
		return fmt.Errorf("failed to read message")
	}
	return nil
}

func sendMessage(stream quic.Stream, msg string) error {
	buf := []byte(msg)
	n, err := stream.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("failed to write all")
	}
	return nil
}

func openAndSend(conn quic.Connection, msg string) error {
	stream, err := conn.OpenStream()
	if err != nil {
		return err
	}
	err = sendMessage(stream, msg)
	if err != nil {
		return err
	}
	return nil
}

func acceptAndReceive(conn quic.Connection, msg string) error {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return err
	}
	err = receiveMessage(stream, msg)
	if err != nil {
		return err
	}
	return nil
}
