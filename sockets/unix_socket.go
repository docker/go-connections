// +build !windows

/*
Package sockets is a simple unix domain socket wrapper.

Usage

For example:

	import(
		"fmt"
		"net"
		"os"
		"github.com/docker/go-connections/sockets"
	)

	func main() {
		l, err := sockets.NewUnixSocketWithOpts("/path/to/sockets",
			sockets.WithChown(0,0),sockets.WithChmod(0660))
		if err != nil {
			panic(err)
		}
		echoStr := "hello"

		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				conn.Write([]byte(echoStr))
				conn.Close()
			}
		}()

		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}

		buf := make([]byte, 5)
		if _, err := conn.Read(buf); err != nil {
			panic(err)
		} else if string(buf) != echoStr {
			panic(fmt.Errorf("Msg may lost"))
		}
	}
*/
package sockets

import (
	"net"
	"os"
	"syscall"
)

// SockOption sets up socket file's creating option
type SockOption func(string) error

// WithChown modifies the socket file's uid and gid
func WithChown(uid, gid int) SockOption {
	return func(path string) error {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
		return nil
	}
}

// WithChmod modifies socket file's access mode
func WithChmod(mask os.FileMode) SockOption {
	return func(path string) error {
		if err := os.Chmod(path, mask); err != nil {
			return err
		}
		return nil
	}
}

// NewUnixSocketWithOpts creates a unix socket with the specified options
func NewUnixSocketWithOpts(path string, opts ...SockOption) (net.Listener, error) {
	// Using syscall.Unlink(), not os.Remove() to prevent deleting the socket if it's in use
	if err := syscall.Unlink(path); err != nil && !os.IsNotExist(err) {
		if err != syscall.EISDIR {
			// On Linux, attempting to remove a directory returns syscall.EISDIR,
			// in which case we try to remove the directory. MacOS does not return
			// this error, so we'll return immediately, see:
			// https://github.com/golang/go/blob/6b420169d798c7ebe733487b56ea5c3fa4aab5ce/src/os/file_unix.go#L300-L311
			return nil, err
		}
		if err := syscall.Rmdir(path); err != nil {
			return nil, err
		}
	}
	mask := syscall.Umask(0777)
	defer syscall.Umask(mask)

	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}

	for _, op := range opts {
		if err := op(path); err != nil {
			l.Close()
			return nil, err
		}
	}

	return l, nil
}

// NewUnixSocket creates a unix socket with the specified path and group.
func NewUnixSocket(path string, gid int) (net.Listener, error) {
	return NewUnixSocketWithOpts(path, WithChown(0, gid), WithChmod(0660))
}
