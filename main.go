package main

import (
	"crypto/tls"
	"fmt"
	"github.com/birneee/hquic-proxy-go/common"
	"github.com/birneee/hquic-proxy-go/proxy"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/urfave/cli/v2"
	"net"
	"os"
	"os/signal"
	"time"
)

const defaultProxyTLSCertificateFile = "proxy.crt"
const defaultProxyTLSKeyFile = "proxy.key"

func main() {

	app := &cli.App{
		Name:  "hquic-proxy-go",
		Usage: "run H-QUIC proxy",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "addr",
				Usage: "address of the proxy to listen on",
				Value: "0.0.0.0",
			},
			&cli.UintFlag{
				Name:  "port",
				Usage: "port of the proxy to listen on, for control connections",
				Value: quic.DefaultHQUICProxyControlPort,
			},
			&cli.StringFlag{
				Name:  "tls-cert",
				Usage: "certificate file to use",
				Value: defaultProxyTLSCertificateFile,
			},
			&cli.StringFlag{
				Name:  "tls-key",
				Usage: "key file to use",
				Value: defaultProxyTLSKeyFile,
			},
			&cli.StringFlag{
				Name:  "next-proxy",
				Usage: "the additional, server-facing proxy to use, in the form \"host:port\", default port 18081 if not specified",
			},
			&cli.StringFlag{
				Name:  "next-proxy-cert",
				Usage: "certificate file to trust the next proxy",
				Value: defaultProxyTLSCertificateFile,
			},
			&cli.UintFlag{
				Name:  "client-facing-initial-congestion-window",
				Usage: "the initial congestion window to use on client facing proxy connections, in number of packets",
				Value: quic.DefaultInitialCongestionWindow,
			},
			&cli.UintFlag{
				Name:  "client-facing-min-congestion-window",
				Usage: "the minimum congestion window to use on client facing proxy connections, in number of packets",
				Value: quic.DefaultMinCongestionWindow,
			},
			&cli.UintFlag{
				Name:  "client-facing-max-congestion-window",
				Usage: "the maximum congestion window to use on client facing proxy connections, in number of packets",
				Value: quic.DefaultMaxCongestionWindow,
			},
			&cli.StringFlag{
				Name:  "client-facing-initial-receive-window",
				Usage: "the initial receive window on the client facing proxy connection, in bytes, overwrites the value from the handover state",
			},
			&cli.StringFlag{
				Name:  "server-facing-initial-receive-window",
				Usage: "the initial receive window on the server facing proxy connection, in bytes, overwrites the value from the handover state",
			},
			&cli.StringFlag{
				Name:  "server-facing-max-receive-window",
				Usage: "the maximum receive window on the server facing proxy connection, in bytes, overwrites the value from the handover state",
			},
			&cli.BoolFlag{
				Name:  "0rtt",
				Usage: "gather 0-RTT information to the next proxy beforehand",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "qlog",
				Usage: "create qlog file",
			},
			&cli.StringFlag{
				Name:  "qlog-prefix",
				Usage: "the prefix of the qlog file name",
				Value: "proxy",
			},
			&cli.StringFlag{
				Name:  "log-prefix",
				Usage: "the prefix of the command line output",
				Value: "",
			},
		},
		Action: func(c *cli.Context) error {
			var nextProxyConf *quic.ProxyConfig
			if c.IsSet("next-proxy") {
				var err error
				nextProxyAddr, err := common.ParseResolveHost(c.String("next-proxy"), quic.DefaultHQUICProxyControlPort)
				if err != nil {
					panic(err)
				}
				nextProxyConf = &quic.ProxyConfig{
					Addr: nextProxyAddr.String(),
					TlsConf: &tls.Config{
						RootCAs:            common.NewCertPoolWithCert(c.String("next-proxy-cert")),
						ClientSessionCache: tls.NewLRUClientSessionCache(1),
						NextProtos:         []string{quic.HQUICProxyALPN},
					},
					Config: &quic.Config{
						TokenStore:           quic.NewLRUTokenStore(1, 1),
						HandshakeIdleTimeout: 10 * time.Second,
					},
				}
			}
			var clientSideInitialReceiveWindow uint64
			if c.IsSet("client-facing-initial-receive-window") {
				var err error
				clientSideInitialReceiveWindow, err = common.ParseByteCountWithUnit(c.String("client-facing-initial-receive-window"))
				if err != nil {
					return fmt.Errorf("failed to parse client-facing-initial-receive-window: %w", err)
				}
			}
			var serverSideInitialReceiveWindow uint64
			if c.IsSet("server-facing-initial-receive-window") {
				var err error
				serverSideInitialReceiveWindow, err = common.ParseByteCountWithUnit(c.String("server-facing-initial-receive-window"))
				if err != nil {
					return fmt.Errorf("failed to parse server-facing-initial-receive-window: %w", err)
				}
			}
			var serverSideMaxReceiveWindow uint64
			if c.IsSet("server-facing-max-receive-window") {
				var err error
				serverSideMaxReceiveWindow, err = common.ParseByteCountWithUnit(c.String("server-facing-max-receive-window"))
				if err != nil {
					return fmt.Errorf("failed to parse server-facing-max-receive-window: %w", err)
				}
			}

			controlTlsCert, err := tls.LoadX509KeyPair(c.String("tls-cert"), c.String("tls-key"))
			if err != nil {
				return err
			}

			logger := common.DefaultLogger.WithPrefix(c.String("log-prefix"))

			var serverFacingTracer logging.Tracer
			var clientFacingTracer logging.Tracer
			if c.Bool("qlog") {
				clientFacingTracer = common.NewQlogTracer(fmt.Sprintf("%s_client_facing", c.String("qlog-prefix")), logger)
				serverFacingTracer = common.NewQlogTracer(fmt.Sprintf("%s_server_facing", c.String("qlog-prefix")), logger)
			}

			if nextProxyConf != nil && c.Bool("0rtt") {
				err := common.PingToGatherSessionTicketAndToken(nextProxyConf.Addr, nextProxyConf.TlsConf, nextProxyConf.Config)
				if err != nil {
					return err
				}
			}

			prox, err := proxy.Run(&proxy.Config{
				Logger: logger,
				ControlConfig: &proxy.ControlConfig{
					Addr: &net.UDPAddr{
						IP:   net.ParseIP(c.String("addr")),
						Port: c.Int("port"),
					},
					TlsConfig: &tls.Config{
						Certificates: []tls.Certificate{controlTlsCert},
					},
				},
				ServerFacingProxyConnectionConfig: &proxy.RestoreConfig{
					ProxyConf:                     nextProxyConf,
					OverwriteInitialReceiveWindow: serverSideInitialReceiveWindow,
					MaxReceiveWindow:              serverSideMaxReceiveWindow,
					Tracer:                        serverFacingTracer,
				},
				ClientFacingProxyConnectionConfig: &proxy.RestoreConfig{
					InitialCongestionWindow:       uint32(c.Uint("client-facing-initial-congestion-window")),
					MinCongestionWindow:           uint32(c.Uint("client-facing-min-congestion-window")),
					MaxCongestionWindow:           uint32(c.Uint("client-facing-max-congestion-window")),
					OverwriteInitialReceiveWindow: clientSideInitialReceiveWindow,
					Tracer:                        clientFacingTracer,
				},
			})
			if err != nil {
				return err
			}

			// close gracefully on interrupt (CTRL+C)
			intChan := make(chan os.Signal, 1)
			signal.Notify(intChan, os.Interrupt)
			<-intChan
			_ = prox.Close()
			os.Exit(0)

			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}
