module github.com/birneee/hquic-proxy-go

go 1.19

replace (
	github.com/lucas-clemente/quic-go => github.com/birneee/quic-go v0.32.1-0.20230309155005-ab6f9fb462b6
	github.com/marten-seemann/qtls-go1-19 => github.com/birneee/qtls-go1-19 v0.1.0
)

require (
	github.com/lucas-clemente/quic-go v0.30.0
	github.com/marten-seemann/qtls-go1-19 v0.1.1
	github.com/urfave/cli/v2 v2.23.0
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/francoispqt/gojay v1.2.13 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/onsi/ginkgo/v2 v2.2.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/exp v0.0.0-20220722155223-a9213eeb770e // indirect
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4 // indirect
	golang.org/x/net v0.0.0-20220722155237-a158d28d115b // indirect
	golang.org/x/sys v0.1.1-0.20221102194838-fc697a31fa06 // indirect
	golang.org/x/tools v0.1.12 // indirect
)
