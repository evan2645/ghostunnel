package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"

	"github.com/armon/go-socks5"
	"golang.org/x/net/context"
)

func serveSocksConn(conn net.Conn) error {
	socksConfig := &socks5.Config{
		Dial:     socksBackendDialer,
		Logger:   logger,
		Resolver: emptyResolver{},
	}

	s, err := socks5.New(socksConfig)
	if err != nil {
		return fmt.Errorf("Error creating SOCKS server: %v", err)
	}

	return s.ServeConn(conn)
}

// Define a dummy resolver so we get access to the FQDN
// in the dialer
type emptyResolver struct{}

func (emptyResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

func socksBackendDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	config, err := buildConfig(*caBundlePath)
	if err != nil {
		return nil, err
	}
	config.ServerName = addr

	cert, err := buildCertificate(*keystorePath, *keystorePass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: unable to load certificates: %s", err)
		return nil, err
	}

	// Perform resolution with the default resolver now that
	// we've configured TLS with an FQDN
	ctx, ip, err := socks5.DNSResolver{}.Resolve(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("Failed to resolve destination '%v': %v", addr, err)
	}

	crt, _ := cert.getCertificate(nil)
	config.Certificates = []tls.Certificate{*crt}
	return tls.DialWithDialer(&net.Dialer{Timeout: *timeoutDuration}, network, ip.String(), config)
}
