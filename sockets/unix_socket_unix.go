//go:build !windows

package sockets

import (
	"net"
	"os"
	"syscall"
)

// WithChown modifies the socket file's uid and gid
func WithChown(uid, gid int) SockOption {
	return func(path string) error {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
		return nil
	}
}

// WithChmod modifies socket file's access mode.
func WithChmod(mask os.FileMode) SockOption {
	return func(path string) error {
		if err := os.Chmod(path, mask); err != nil {
			return err
		}
		return nil
	}
}

// NewUnixSocket creates a unix socket with the specified path and group.
func NewUnixSocket(path string, gid int) (net.Listener, error) {
	return NewUnixSocketWithOpts(path, WithChown(0, gid), WithChmod(0o660))
}

func listenUnix(path string, opts ...SockOption) (_ net.Listener, retErr error) {
	// net.Listen does not allow permissions or ownership to be set between
	// bind(2), which creates the socket path, and listen(2), which makes it
	// possible for clients to connect.
	//
	// Creating the socket manually lets us apply options after bind(2), but
	// before listen(2). This avoids temporarily relaxing the process umask while
	// still preventing a socket from becoming connectable before the requested
	// permissions are applied.
	//
	// See https://github.com/golang/go/issues/11822
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd) // No syscall.SOCK_CLOEXEC on macOS.
	defer func() {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
	}()

	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		return nil, err
	}

	defer func() {
		if retErr != nil {
			_ = syscall.Unlink(path)
		}
	}()

	// Preserve the previous secure-by-default behavior: the socket is not
	// accessible at all unless permission options are set.
	//
	// TODO(thaJeztah): consider using "0600" as default; using "0000" could potentially mean we can't cleanup on error.
	if err := os.Chmod(path, 0); err != nil {
		return nil, err
	}

	for _, op := range opts {
		if err := op(path); err != nil {
			return nil, err
		}
	}

	if err := syscall.Listen(fd, syscall.SOMAXCONN); err != nil {
		return nil, err
	}

	f := os.NewFile(uintptr(fd), "unix:"+path)
	fd = -1 // f now owns the original fd; prevent the defer from closing it.

	// FileListener takes ownership of the socket; f is only a temporary wrapper,
	// and the temporary *os.File is no longer needed after this point.
	l, err := net.FileListener(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}

	if ul, ok := l.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}

	return l, nil
}
