// +build !windows

package sockets

import (
	"net"
	"os"
	"syscall"
)

// Usage:
//     l, err := sockets.NewUnixSocket("/path/to/sockets",sockets.WithChown(0,0),sockets.WithChmod(0660))

type SockOption func(string) error

func WithChown(uid, gid int) SockOption {
	return func(path string) error {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
		return nil
	}
}

func WithChmod(mask os.FileMode) SockOption {
	return func(path string) error {
		if err := os.Chmod(path, mask); err != nil {
			return err
		}
		return nil
	}
}

// NewUnixSocket creates a unix socket with the specified options
func NewUnixSocketWithOpts(path string, opts ...func(string) error) (net.Listener, error) {
	if err := syscall.Unlink(path); err != nil && !os.IsNotExist(err) {
		return nil, err
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
func NewUnixSocket(path string, uid int) (net.Listener, error) {
	return NewUnixSocketWithOpts(path, WithChown(uid, 0), WithChmod(0666))
}
