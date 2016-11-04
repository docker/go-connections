// +build windows

package sockets

import (
	"net"

	"github.com/Microsoft/go-winio"
)

// NewWindowsSocket creates a Windows named pipe on the specified path.
func NewWindowsSocket(addr string, pipeConfig *winio.PipeConfig) (net.Listener, error) {
	listener, err := winio.ListenPipe(addr, pipeConfig)
	if err != nil {
		return nil, err
	}
	return listener, nil
}
