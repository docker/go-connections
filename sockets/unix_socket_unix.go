//go:build !windows

package sockets

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// WithChown modifies the socket file's uid and gid.
//
// Abstract Unix sockets have no filesystem representation, so this option
// returns an error wrapping [errors.ErrUnsupported] when used with an abstract
// socket.
func WithChown(uid, gid int) SockOption {
	return func(path string) error {
		if isAbstractSocket(path) {
			return &os.PathError{
				Op:   "chown",
				Path: path,
				Err:  fmt.Errorf("abstract Unix sockets do not support filesystem permissions: %w", errors.ErrUnsupported),
			}
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
		return nil
	}
}

// WithChmod modifies socket file's access mode.
//
// Abstract Unix sockets have no filesystem representation, so this option
// returns an error wrapping [errors.ErrUnsupported] when used with an abstract
// socket.
func WithChmod(mask os.FileMode) SockOption {
	return func(path string) error {
		if isAbstractSocket(path) {
			return &os.PathError{
				Op:   "chmod",
				Path: path,
				Err:  fmt.Errorf("abstract Unix sockets do not support filesystem permissions: %w", errors.ErrUnsupported),
			}
		}
		if err := os.Chmod(path, mask); err != nil {
			return err
		}
		return nil
	}
}

// NewUnixSocket creates a Unix socket with the specified path and group.
//
// On Unix platforms, the socket is owned by root:gid and has permissions 0660.
//
// Abstract Unix sockets are not supported by this helper. Use [NewUnixSocketWithOpts]
// without filesystem permission options instead.
func NewUnixSocket(path string, gid int) (net.Listener, error) {
	return NewUnixSocketWithOpts(path, WithChown(0, gid), WithChmod(0o660))
}

func listenUnix(path string) (net.Listener, error) {
	// net.Listen does not allow for permissions to be set. As a result, when
	// specifying custom permissions ("WithChmod()"), there is a short time
	// between creating the socket and applying the permissions, during which
	// the socket permissions are Less restrictive than desired.
	//
	// To work around this limitation of net.Listen(), we temporarily set the
	// umask to 0777, which forces the socket to be created with 000 permissions
	// (i.e.: no access for anyone). After that, WithChmod() must be used to set
	// the desired permissions.
	//
	// We don't use "defer" here, to reset the umask to its original value as soon
	// as possible. Ideally we'd be able to detect if WithChmod() was passed as
	// an option, and skip changing umask if default permissions are used.
	origUmask := syscall.Umask(0o777)
	l, err := net.Listen("unix", path)
	syscall.Umask(origUmask)
	return l, err
}
