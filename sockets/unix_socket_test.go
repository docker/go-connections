package sockets

import (
	"fmt"
	"net"
	"os"
	"testing"
)

// Use the macOS limit (104 bytes), which is lower than Linux's 108-byte
// limit, so tests pass on both platforms.
const maxSocketPathLen = 104

// tempSocketPath returns a temporary socket path short enough to avoid
// exceeding Unix-domain socket path length limits on some platforms.
func tempSocketPath(t *testing.T) string {
	t.Helper()

	f, err := os.CreateTemp("", "test*.sock")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	path := f.Name()
	t.Cleanup(func() { _ = os.Remove(path) })
	if len(path) >= maxSocketPathLen {
		t.Fatalf("temporary socket path too long (%d >= %d): %q", len(path), maxSocketPathLen, path)
	}
	// Remove the temporary file; we only need a unique path / name.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	return path
}

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
