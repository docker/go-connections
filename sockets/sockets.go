// Package sockets provides helper functions to create and configure Unix or TCP sockets.
package sockets

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

const (
	defaultTimeout        = 10 * time.Second
	maxUnixSocketPathSize = len(syscall.RawSockaddrUnix{}.Path)
)

// ErrProtocolNotAvailable is returned when a given transport protocol is not provided by the operating system.
var ErrProtocolNotAvailable = errors.New("protocol not available")

// ConfigureTransport configures the specified [http.Transport] according to the specified proto
// and addr.
//
// If the proto is unix (using a unix socket to communicate) or npipe the compression is disabled.
// For other protos, compression is enabled. If you want to manually enable/disable compression,
// make sure you do it _after_ any subsequent calls to ConfigureTransport is made against the same
// [http.Transport].
func ConfigureTransport(tr *http.Transport, proto, addr string) error {
	if tr.MaxIdleConns == 0 {
		// prevent long-lived processes from leaking connections
		// due to idle connections not being released.
		//
		// TODO: see if we can also address this from the server side; see: https://github.com/moby/moby/issues/45539
		tr.MaxIdleConns = 6
		tr.IdleConnTimeout = 30 * time.Second
	}
	switch proto {
	case "unix":
		return configureUnixTransport(tr, addr)
	case "npipe":
		return configureNpipeTransport(tr, addr)
	default:
		tr.Proxy = TCPProxyFromEnvironment
		tr.DisableCompression = false
		tr.DialContext = (&net.Dialer{
			Timeout: defaultTimeout,
		}).DialContext
	}
	return nil
}

func configureUnixTransport(tr *http.Transport, addr string) error {
	if len(addr) > maxUnixSocketPathSize {
		return fmt.Errorf("unix socket path %q is too long", addr)
	}
	// No need for compression in local communications.
	tr.DisableCompression = true
	dialer := &net.Dialer{
		Timeout: defaultTimeout,
	}
	tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", addr)
	}
	return nil
}

// TCPProxyFromEnvironment wraps [http.ProxyFromEnvironment] to preserve the
// pre-go1.16 behavior for URLs using the 'tcp://' scheme. For other schemes,
// golang's standard behavior is preserved (and depends on the Go version used).
//
// Prior to go1.16, "https://" schemes would use HTTPS_PROXY, and any other
// scheme would use HTTP_PROXY. However, https://github.com/golang/net/commit/7b1cca2348c07eb09fef635269c8e01611260f9f
// (per a request in golang/go#40909) changed this behavior to only use
// HTTP_PROXY for "http://" schemes, no longer using a proxy for any other
// scheme.
//
// Docker uses the "tcp://" scheme as a default for API connections, to indicate
// that the API is not "purely" HTTP. Various parts in the code also *require*
// this scheme to be used. While we could change the default and allow http(s)
// schemes to be used, doing so will take time, taking into account that there
// are many installs in existence that have "tcp://" configured as DOCKER_HOST.
//
// This function detects if the "tcp://" scheme is used; if it is, it creates
// a shallow copy of req, containing just the URL, and overrides the scheme with
// "http", which should be sufficient to perform proxy detection.
// For other (non-"tcp://") schemes, [http.ProxyFromEnvironment] is called without
// altering the request.
func TCPProxyFromEnvironment(req *http.Request) (*url.URL, error) {
	if req.URL.Scheme != "tcp" {
		return http.ProxyFromEnvironment(req)
	}
	u := req.URL
	if u.Scheme == "tcp" {
		u.Scheme = "http"
	}
	return http.ProxyFromEnvironment(&http.Request{URL: u})
}
