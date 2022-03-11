package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/birneee/hquic-proxy-go/internal/testdata"
	"github.com/lucas-clemente/quic-go"
	"reflect"
	"testing"
)

func transmitMessages(from quic.Session, to quic.Session) error {
	writer, err := from.OpenStream()
	if err != nil {
		return err
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

var clientConfig = &quic.Config{
	EnableActiveMigration: true,
}

var serverConfig = &quic.Config{
	EnableActiveMigration: true,
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
	proxy, err := ListenAddr("127.0.0.1:0", proxyTlsConfig, nil, nil)
	if err != nil {
		t.Errorf(err.Error())
	}
	server, err := quic.ListenAddr("127.0.0.1:0", serverTlsConfig, serverConfig)
	if err != nil {
		t.Errorf(err.Error())
	}
	clientConfig := clientConfig.Clone()
	clientConfig.ProxyConf = &quic.ProxyConfig{
		Addr:    proxy.Addr().String(),
		TlsConf: clientTlsConfig,
	}
	client, err := quic.DialAddr(server.Addr().String(), clientTlsConfig, clientConfig)
	if err != nil {
		t.Errorf(err.Error())
	}
	serverSession, err := server.Accept(context.Background())
	if err != nil {
		t.Errorf(err.Error())
	}
	err = transmitMessages(client, serverSession)
	if err != nil {
		t.Errorf(err.Error())
	}
	err = transmitMessages(serverSession, client)
	if err != nil {
		t.Errorf(err.Error())
	}
	err = server.Close()
	if err != nil {
		t.Errorf(err.Error())
	}
}

func TestTwoProxy(t *testing.T) {
	proxy2, err := ListenAddr("127.0.0.1:0", proxyTlsConfig, nil, nil)
	if err != nil {
		t.Errorf(err.Error())
	}
	proxy1, err := ListenAddr("127.0.0.1:0", proxyTlsConfig, nil, &ProxyConfig{
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
	serverSession, err := server.Accept(context.Background())
	if err != nil {
		t.Errorf(err.Error())
	}
	err = transmitMessages(client, serverSession)
	if err != nil {
		t.Errorf(err.Error())
	}
	err = transmitMessages(serverSession, client)
	if err != nil {
		t.Errorf(err.Error())
	}
	err = server.Close()
	if err != nil {
		t.Errorf(err.Error())
	}
}
