package main

import (
	"github.com/birneee/hquic-proxy-go/proxy"
	"github.com/urfave/cli/v2"
	"net"
	"os"
)

const defaultProxyControlPort = 18081
const defaultTLSCertificateFile = "proxy.crt"
const defaultTLSKeyFile = "proxy.key"

func main() {
	app := &cli.App{
		Name:  "hquic-proxy-go",
		Usage: "TODO",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "addr",
				Usage: "address of the proxy to listen on",
				Value: "0.0.0.0",
			},
			&cli.UintFlag{
				Name:  "port",
				Usage: "port of the proxy to listen on, for control connections",
				Value: defaultProxyControlPort,
			},
			&cli.StringFlag{
				Name:  "tls-cert",
				Usage: "certificate file to use",
				Value: defaultTLSCertificateFile,
			},
			&cli.StringFlag{
				Name:  "tls-key",
				Usage: "key file to use",
				Value: defaultTLSKeyFile,
			},
		},
		Action: func(c *cli.Context) error {
			proxy.RunProxy(
				net.UDPAddr{
					IP:   net.ParseIP(c.String("addr")),
					Port: c.Int("port"),
				},
				c.String("tls-cert"),
				c.String("tls-key"),
			)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}
