package main

import (
	"github.com/urfave/cli/v2"
	"hquic-proxy-go/proxy"
	"net"
	"os"
)

const defaultProxyControlPort = 18081

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
				Value: "proxy.crt",
			},
			&cli.StringFlag{
				Name:  "tls-key",
				Usage: "key file to use",
				Value: "proxy.key",
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
