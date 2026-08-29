package sockets

import (
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestNewTCPSocketPreservesConfiguredNextProtos(t *testing.T) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{loadSocketTestCertificate(t)},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	wantProtos := append([]string(nil), tlsConfig.NextProtos...)

	l, err := NewTCPSocket("127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSocketListener(t, l)

	got, err := negotiateSocketProtocol(t, l, []string{"h2"})
	if err != nil {
		t.Fatalf("negotiating h2: %v", err)
	}
	if got != "h2" {
		t.Fatalf("negotiated protocol = %q, want h2", got)
	}
	if !reflect.DeepEqual(tlsConfig.NextProtos, wantProtos) {
		t.Fatalf("NewTCPSocket mutated NextProtos to %v, want %v", tlsConfig.NextProtos, wantProtos)
	}
}

func TestNewTCPSocketDefaultsNextProto(t *testing.T) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{loadSocketTestCertificate(t)},
	}

	l, err := NewTCPSocket("127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSocketListener(t, l)

	got, err := negotiateSocketProtocol(t, l, []string{"http/1.1"})
	if err != nil {
		t.Fatalf("negotiating http/1.1: %v", err)
	}
	if got != "http/1.1" {
		t.Fatalf("negotiated protocol = %q, want http/1.1", got)
	}
	if len(tlsConfig.NextProtos) != 0 {
		t.Fatalf("NewTCPSocket mutated caller NextProtos to %v", tlsConfig.NextProtos)
	}
}

func loadSocketTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	cert, err := tls.LoadX509KeyPair("../tlsconfig/fixtures/cert.pem", "../tlsconfig/fixtures/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func negotiateSocketProtocol(t *testing.T, l net.Listener, clientProtos []string) (string, error) {
	t.Helper()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			serverErr <- err
			return
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			serverErr <- conn.Close()
			return
		}
		err = tlsConn.Handshake()
		if closeErr := conn.Close(); err == nil {
			err = closeErr
		}
		serverErr <- err
	}()

	conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         clientProtos,
	})
	if err != nil {
		_ = l.Close()
		_ = waitForSocketServer(t, serverErr)
		return "", err
	}

	if err := waitForSocketServer(t, serverErr); err != nil {
		_ = conn.Close()
		return "", err
	}
	protocol := conn.ConnectionState().NegotiatedProtocol
	if err := conn.Close(); err != nil {
		return "", err
	}
	return protocol, nil
}

func waitForSocketServer(t *testing.T, serverErr <-chan error) error {
	t.Helper()

	select {
	case err := <-serverErr:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server handshake")
	}
	return nil
}

func closeSocketListener(t *testing.T, l net.Listener) {
	t.Helper()

	if err := l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("closing listener: %v", err)
	}
}
