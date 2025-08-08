//go:build !windows

package sockets

import "net/http"

func configureNpipeTransport(tr *http.Transport, proto, addr string) error {
	return ErrProtocolNotAvailable
}
