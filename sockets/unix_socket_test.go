//go:build !windows

package sockets

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"runtime"
	"syscall"
	"testing"
)

func runTest(t *testing.T, path string, l net.Listener, echoStr string) {
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte(echoStr))
			_ = conn.Close()
		}
	}()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	} else if string(buf) != echoStr {
		t.Fatal(fmt.Errorf("msg may lost"))
	}
}

// TestNewUnixSocket run under root user.
func TestNewUnixSocket(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	gid := os.Getgid()
	path := "/tmp/test.sock"
	echoStr := "hello"
	l, err := NewUnixSocket(path, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	runTest(t, path, l, echoStr)
}

func TestUnixSocketWithOpts(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	perms := os.FileMode(0o660)
	path := "/tmp/test.sock"
	echoStr := "hello"
	l, err := NewUnixSocketWithOpts(path, WithChown(uid, gid), WithChmod(perms))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	p, err := os.Stat(path)
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
	runTest(t, path, l, echoStr)
}

func TestUnixSocketConflictDirectory(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	t.Run("conflicting directory", func(t *testing.T) {
		if runtime.GOOS == "darwin" {
			t.Skip("not supported on macOS")
		}
		path := path.Join(tmpDir, "test.sock")

		// Create a conflicting directory at the socket location
		err = os.MkdirAll(path, 0700)
		if err != nil {
			t.Fatal(err)
		}

		l, err := NewUnixSocketWithOpts(path)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		runTest(t, path, l, "hello")
	})

	t.Run("conflicting file", func(t *testing.T) {
		// Create a conflicting file at the socket location
		path := path.Join(tmpDir, "test2.sock")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()

		l, err := NewUnixSocketWithOpts(path)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		runTest(t, path, l, "hello")
	})
}
