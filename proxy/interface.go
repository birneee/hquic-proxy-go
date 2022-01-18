package proxy

import "net"

type Proxy interface {
	// Addr returns the local network addr that the server is listening on.
	Addr() net.Addr
	// Close the proxy. All active sessions will be closed.
	Close() error
}
