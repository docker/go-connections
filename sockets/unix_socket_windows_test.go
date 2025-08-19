package sockets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetSecurityDescriptor(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		sddl, err := getSecurityDescriptor()
		if err != nil {
			t.Error(err)
		}
		expected := BasePermissions
		if sddl != expected {
			t.Errorf("expected: %s, got: %s", expected, sddl)
		}
	})
	t.Run("Users", func(t *testing.T) {
		const name = "Users" // for testing, should always be available
		sddl, err := getSecurityDescriptor(name)
		if err != nil {
			t.Error(err)
		}
		// FIXME(thaJeztah): this may not be a reproducible SID; probably should do some fuzzy matching.
		const expected = "D:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGW;;;S-1-5-32-545)"
		if sddl != expected {
			t.Errorf("expected: %s, got: %s", expected, sddl)
		}
	})

	// TODO(thaJeztah): should this fail on duplicate users?
	t.Run("Users twice", func(t *testing.T) {
		const name = "Users" // for testing, should always be available
		sddl, err := getSecurityDescriptor(name, name)
		if err != nil {
			t.Error(err)
		}
		// FIXME(thaJeztah): this may not be a reproducible SID; probably should do some fuzzy matching.
		const expected = "D:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGW;;;S-1-5-32-545)(A;;GRGW;;;S-1-5-32-545)"
		if sddl != expected {
			t.Errorf("expected: %s, got: %s", expected, sddl)
		}
	})
	t.Run("NoSuchUserOrGroup", func(t *testing.T) {
		const name = "NoSuchUserOrGroup" // non-existing user or group
		sddl, err := getSecurityDescriptor(name)
		if sddl != "" {
			t.Errorf("expected an empty sddl, got: %s", sddl)
		}
		if err == nil {
			t.Error("expected error")
		}

		const expected = "looking up SID: lookup account NoSuchUserOrGroup: not found"
		if errMsg := err.Error(); errMsg != expected {
			t.Errorf("expected: %s, got: %s", expected, errMsg)
		}
	})
}

func TestUnixSocketWithOpts(t *testing.T) {
	socketFile, err := os.CreateTemp("", "test*.sock")
	if err != nil {
		t.Fatal(err)
	}
	_ = socketFile.Close()
	defer func() { _ = os.Remove(socketFile.Name()) }()

	l, err := NewUnixSocketWithOpts(socketFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	echoStr := "hello"
	runTest(t, socketFile.Name(), l, echoStr)
}

func TestNewUnixSocket(t *testing.T) {
	group := "Users" // for testing, should always be available
	socketPath := filepath.Join(os.TempDir(), "test.sock")
	defer func() { _ = os.Remove(socketPath) }()
	t.Logf("socketPath: %s, path length: %d", socketPath, len(socketPath))

	l, err := NewUnixSocket(socketPath, []string{group})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	runTest(t, socketPath, l, "hello")
}

func TestNewUnixSocketUnknownGroup(t *testing.T) {
	group := "NoSuchUserOrGroup"
	socketPath := filepath.Join(os.TempDir(), "fail.sock")
	_, err := NewUnixSocket(socketPath, []string{group})
	_ = os.Remove(socketPath)
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}
