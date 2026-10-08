package sockets

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestNewTCPSocketALPN(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	defer certServer.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())

	for _, tc := range []struct {
		name       string
		server     []string
		client     []string
		negotiated string
	}{
		{name: "default", client: []string{"http/1.1"}, negotiated: "http/1.1"},
		{name: "empty", server: []string{}, client: []string{"http/1.1"}, negotiated: "http/1.1"},
		{name: "h2", server: []string{"h2", "http/1.1"}, client: []string{"h2"}, negotiated: "h2"},
		{name: "http1", server: []string{"h2", "http/1.1"}, client: []string{"http/1.1"}, negotiated: "http/1.1"},
		{name: "no_alpn", server: []string{"h2", "http/1.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &tls.Config{
				Certificates: certServer.TLS.Certificates,
				NextProtos:   slices.Clone(tc.server),
				MinVersion:   tls.VersionTLS12,
			}
			listener, err := NewTCPSocket("127.0.0.1:0", config)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			if !reflect.DeepEqual(config.NextProtos, tc.server) {
				t.Errorf("NextProtos changed: got %#v, want %#v", config.NextProtos, tc.server)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			handshake := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					handshake <- err
					return
				}
				defer func() { _ = conn.Close() }()
				handshake <- conn.(*tls.Conn).HandshakeContext(ctx)
			}()

			dialer := tls.Dialer{Config: &tls.Config{
				RootCAs:    roots,
				NextProtos: tc.client,
				MinVersion: tls.VersionTLS12,
			}}
			conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := <-handshake; err != nil {
				t.Fatal(err)
			}
			if got := conn.(*tls.Conn).ConnectionState().NegotiatedProtocol; got != tc.negotiated {
				t.Errorf("negotiated protocol = %q, want %q", got, tc.negotiated)
			}
		})
	}
}
