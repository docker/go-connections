// +build appengine

package sockets

import (
	"errors"
	"net"
	"time"
)

// DialPipe connects to a Windows named pipe.
// This is not supported on other OSes.
func DialPipe(_ string, _ time.Duration) (net.Conn, error) {
	return nil, errors.New("no support")
}
