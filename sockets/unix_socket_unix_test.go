//go:build !windows

package sockets

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestUnixSocketWithOpts(t *testing.T) {
	socketPath := tempSocketPath(t)

	uid, gid := os.Getuid(), os.Getgid()
	perms := os.FileMode(0660)
	l, err := NewUnixSocketWithOpts(socketPath, WithChown(uid, gid), WithChmod(perms))
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.Stat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode().Perm() != perms {
		t.Fatalf("unexpected file permissions: expected: %#o, got: %#o", perms, p.Mode().Perm())
	}
	if stat, ok := p.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != uint32(uid) || stat.Gid != uint32(gid) {
			t.Fatalf("unexpected file ownership: expected: %d:%d, got: %d:%d", uid, gid, stat.Uid, stat.Gid)
		}
	}

	defer func() { _ = l.Close() }()

	echoStr := "hello"
	runTest(t, socketPath, l, echoStr)
}

// TestUnixSocketWithOptsDefaultPermissions verifies that sockets created
// without an explicit WithChmod option have permissions set to 0000.
func TestUnixSocketWithOptsDefaultPermissions(t *testing.T) {
	socketPath := tempSocketPath(t)
	l, err := NewUnixSocketWithOpts(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatal(err)
	}

	const wantPerms os.FileMode = 0o000
	if got := info.Mode().Perm(); got != wantPerms {
		t.Fatalf("unexpected file permissions: expected: %#o, got: %#o", wantPerms, got)
	}
}

// TestUnixSocketWithOptsCleanupOnError verifies that partially initialized
// sockets are cleaned up when a socket option returns an error.
func TestUnixSocketWithOptsCleanupOnError(t *testing.T) {
	socketPath := tempSocketPath(t)

	wantErr := errors.New("boom")
	_, err := NewUnixSocketWithOpts(socketPath, func(string) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected error %v, got %v", wantErr, err)
	}

	if _, err := os.Lstat(socketPath); err == nil {
		t.Fatalf("socket %q still exists", socketPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("unexpected error stating %q: %v", socketPath, err)
	}
}

// TestNewUnixSocket run under root user.
func TestNewUnixSocket(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	gid := os.Getgid()
	socketPath := tempSocketPath(t)
	echoStr := "hello"
	l, err := NewUnixSocket(socketPath, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	runTest(t, socketPath, l, echoStr)
}

// TestNewUnixSocketWithOptsAbstract verifies that abstract Unix sockets behave
// correctly. Unlike filesystem-backed sockets, they must not create a socket
// file before or after the listener is closed.
func TestNewUnixSocketWithOptsAbstract(t *testing.T) {
	// Go documents "@" as a Linux-specific shorthand for abstract Unix sockets:
	//
	//   "On Linux, a Name beginning with '@' denotes an abstract socket address:
	//    the '@' is translated to a NUL byte when the address is passed to the
	//    kernel..."
	//
	// See https://pkg.go.dev/net@go1.27rc2#UnixAddr.
	//
	// Linux also accepts the native kernel representation (a leading NUL byte),
	// so both forms are tested here. See https://github.com/golang/go/issues/78615.
	prefixes := []struct{ name, prefix string }{
		{name: "at_prefix", prefix: "@"},
		{name: "nul_prefix", prefix: "\x00"},
	}

	tests := []struct {
		name string
		opts []SockOption
	}{
		{
			name: "no_options",
		},
		{
			name: "chmod",
			opts: []SockOption{
				WithChmod(0o660),
			},
		},
		{
			name: "chown",
			opts: []SockOption{
				WithChown(os.Getuid(), os.Getgid()),
			},
		},
	}

	for _, prefix := range prefixes {
		t.Run(prefix.name, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					socketPath := prefix.prefix + filepath.Base(tempSocketPath(t))

					l, err := NewUnixSocketWithOpts(socketPath, tc.opts...)
					wantErr := !supportsAbstractSockets || len(tc.opts) > 0
					if wantErr {
						if err == nil {
							_ = l.Close()
							t.Fatalf("expected abstract socket %q to be rejected", socketPath)
						}
						if !errors.Is(err, errors.ErrUnsupported) {
							t.Fatalf("expected unsupported error, got %v", err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if prefix.prefix != "\x00" { // can't stat NUL-prefixed paths.
						if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
							t.Fatalf("expected no filesystem entry for abstract socket %q, got %v", socketPath, err)
						}
					}

					runTest(t, socketPath, l, "hello")
					if err := l.Close(); err != nil {
						t.Fatal(err)
					}
					if prefix.prefix != "\x00" { // can't stat NUL-prefixed paths.
						if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
							t.Fatalf("expected no filesystem entry after Close() for abstract socket %q, got %v", socketPath, err)
						}
					}
				})
			}
		})
	}
}
