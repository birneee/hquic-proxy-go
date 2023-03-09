package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/birneee/hquic-proxy-go/common"
	"github.com/birneee/hquic-proxy-go/internal/testdata"
	"github.com/lucas-clemente/quic-go"
	"io"
	"math/rand"
	"net"
	"reflect"
	"sync"
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

var mbMessage1 string
var mbMessage2 string

func init() {
	mbMessage1 = randomString(1e6)
	mbMessage2 = randomString(1e6)
}

var runes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = runes[rand.Intn(len(runes))]
	}
	return string(b)
}

var clientConfig = &quic.Config{
	EnableActiveMigration:      true,
	MaxIdleTimeout:             time.Second,
	InitialStreamReceiveWindow: 1000, //TODO allow larger window
	MaxStreamReceiveWindow:     1000, //TODO allow larger window
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
		err = acceptAndReceive(serverConn, message, true)
		if err != nil {
			t.Errorf(err.Error())
		}
		err = openAndSend(serverConn, message, true)
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
	proxyConf := &quic.ProxyConfig{
		Addr:    proxyAddr.String(),
		TlsConf: proxyControlTlsConfig,
	}

	serverAddr := <-serverAddrChan
	client, err := quic.DialAddrEarly(serverAddr.String(), clientTlsConfig, clientConfig)
	if err != nil {
		t.Errorf(err.Error())
	}
	res := client.AddProxy(proxyConf)
	if res.Error != nil {
		t.Errorf(res.Error.Error())
	}
	if res.Early != allowEarlyHandover {
		t.Errorf("handover was not early, i.e. before handshake is confirmed")
	}

	err = openAndSend(client, message, true)
	if err != nil {
		t.Errorf(err.Error())
	}
	err = acceptAndReceive(client, message, true)
	if err != nil {
		t.Errorf(err.Error())
	}

	<-serverContext.Done()
	<-proxyContext.Done()
}

func TestProxyWithUpAndDownloadStream(t *testing.T) {
	testProxyWithStream(t, true, true)
}

func TestProxyWithUploadStream(t *testing.T) {
	testProxyWithStream(t, false, true)
}

func TestProxyWithDownloadStream(t *testing.T) {
	testProxyWithStream(t, true, false)
}

func testProxyWithStream(t *testing.T, download bool, upload bool) {
	var wgDone sync.WaitGroup
	var wgClosed sync.WaitGroup
	wgDone.Add(3)
	wgClosed.Add(3)
	proxyAddrChan := make(chan net.Addr, 1)
	go func() { // proxy
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
		wgDone.Done()
		wgDone.Wait()
		proxy.Close()
		wgClosed.Done()
	}()
	serverAddrChan := make(chan net.Addr, 1)
	go func() { // server
		server, err := quic.ListenAddr("127.0.0.1:0", serverTlsConfig, serverConfig)
		if err != nil {
			t.Errorf(err.Error())
		}
		serverAddrChan <- server.Addr()
		serverConn, err := server.Accept(context.Background())
		if err != nil {
			t.Errorf(err.Error())
		}
		var wgStream sync.WaitGroup
		if upload {
			wgStream.Add(1)
			go func() { // in stream
				err := acceptAndReceive(serverConn, mbMessage1, true)
				if err != nil {
					t.Errorf(err.Error())
				}
				wgStream.Done()
			}()
		}
		if download {
			wgStream.Add(1)
			go func() { // out stream
				err := openAndSend(serverConn, mbMessage2, true)
				if err != nil {
					t.Errorf(err.Error())
				}
				wgStream.Done()
			}()
		}
		wgStream.Wait()
		wgDone.Done()
		wgDone.Wait()
		server.Close()
		wgClosed.Done()
	}()
	go func() { // client
		proxyAddr := <-proxyAddrChan
		serverAddr := <-serverAddrChan
		client, err := quic.DialAddr(serverAddr.String(), clientTlsConfig, clientConfig)
		if err != nil {
			t.Errorf(err.Error())
		}
		var outStream quic.Stream
		if upload {
			outStream, err = client.OpenStream()
			if err != nil {
				t.Errorf(err.Error())
			}
			err = sendMessage(outStream, mbMessage1[:len(mbMessage1)/2], false)
			if err != nil {
				t.Errorf(err.Error())
			}
		}
		var inStream quic.Stream
		if download {
			inStream, err = client.AcceptStream(context.Background())
			if err != nil {
				t.Errorf(err.Error())
			}
			err = receiveMessage(inStream, mbMessage2[:len(mbMessage2)/2], false)
			if err != nil {
				t.Errorf(err.Error())
			}
		}
		res := client.AddProxy(&quic.ProxyConfig{
			Addr:    proxyAddr.String(),
			TlsConf: proxyControlTlsConfig,
		})
		if res.Error != nil {
			t.Errorf(res.Error.Error())
		}
		<-client.AwaitPathUpdate()
		if upload {
			err = sendMessage(outStream, mbMessage1[len(mbMessage1)/2:], true)
			if err != nil {
				t.Errorf(err.Error())
			}
		}
		if download {
			err = receiveMessage(inStream, mbMessage2[len(mbMessage2)/2:], true)
			if err != nil {
				t.Errorf(err.Error())
			}
		}
		wgDone.Done()
		wgDone.Wait()
		//client.CloseWithError(quic.ApplicationErrorCode(0), "exit")
		wgClosed.Done()
	}()
	wgClosed.Wait()
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
	<-client.AwaitPathUpdate() // open streams after migration
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

func receiveMessage(stream quic.ReceiveStream, msg string, checkEOF bool) error {
	buf := make([]byte, len(msg))
	n, err := io.ReadAtLeast(stream, buf, len(msg))
	if err != nil {
		return err
	}
	if string(buf[:n]) != msg {
		return fmt.Errorf("failed to read message: expected \"%s\" but received \"%s\"", msg, buf[:n])
	}
	if checkEOF {
		err := checkStreamEOF(stream)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkStreamEOF(stream quic.ReceiveStream) error {
	buf := make([]byte, 1)
	n, err := stream.Read(buf)
	if err != io.EOF || n != 0 {
		return fmt.Errorf("not at EOF")
	}
	return nil
}

func sendMessage(stream quic.Stream, msg string, closeStreamAfterWrite bool) error {
	buf := []byte(msg)
	n, err := stream.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("failed to write all")
	}
	if closeStreamAfterWrite {
		err := stream.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func openAndSend(conn quic.Connection, msg string, closeStreamAfterWrite bool) error {
	stream, err := conn.OpenStream()
	if err != nil {
		return err
	}
	err = sendMessage(stream, msg, closeStreamAfterWrite)
	if err != nil {
		return err
	}
	return nil
}

func acceptAndReceive(conn quic.Connection, msg string, checkEOF bool) error {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return err
	}
	err = receiveMessage(stream, msg, checkEOF)
	if err != nil {
		return err
	}
	return nil
}
