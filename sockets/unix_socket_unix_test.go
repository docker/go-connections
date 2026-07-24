//go:build !windows

package sockets

import (
	"errors"
	"os"
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
