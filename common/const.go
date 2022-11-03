package common

import "net"

// TODO IANA registration
const HQUICProxyALPN = "qproxy"
const DefaultProxyControlPort = 18081

var IPv4loopback = net.IPv4(127, 0, 0, 1)
