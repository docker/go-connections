package sockets

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// wellKnownAccountName returns the localized account name for a well-known SID.
//
// Windows defines many built-in users and groups by stable well-known SIDs
// (for example, WinBuiltinUsersSid == S-1-5-32-545), but their display names
// are localized (for example, "Users" on English systems). This helper
// constructs the well-known SID and resolves it to the local account name so
// tests do not depend on the installation language.
func wellKnownAccountName(t *testing.T, sidType windows.WELL_KNOWN_SID_TYPE) string {
	t.Helper()

	sid, err := windows.CreateWellKnownSid(sidType)
	if err != nil {
		t.Fatal(err)
	}

	account, _, _, err := sid.LookupAccount("")
	if err != nil {
		t.Fatal(err)
	}
	return account
}

func TestGetSecurityDescriptor(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		sddl, err := getSecurityDescriptor()
		if err != nil {
			t.Fatal(err)
		}
		expected := BasePermissions
		if sddl != expected {
			t.Errorf("expected: %s, got: %s", expected, sddl)
		}
	})
	t.Run("Users", func(t *testing.T) {
		name := wellKnownAccountName(t, windows.WinBuiltinUsersSid)
		sddl, err := getSecurityDescriptor(name)
		if err != nil {
			t.Fatal(err)
		}

		// S-1-5-32-545 is the well-known SID for the built-in Users group.
		// https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
		const expected = "D:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGW;;;S-1-5-32-545)"
		if sddl != expected {
			t.Errorf("expected: %s, got: %s", expected, sddl)
		}
	})

	// Two identical allow ACEs are redundant, but they do not create
	// conflicting permissions, so should not error.
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
	t.Run("Users twice", func(t *testing.T) {
		name := wellKnownAccountName(t, windows.WinBuiltinUsersSid)
		sddl, err := getSecurityDescriptor(name, name)
		if err != nil {
			t.Fatal(err)
		}

		// S-1-5-32-545 is the well-known SID for the built-in Users group.
		// https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
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
			t.Fatal("expected error")
		}

		const expected = "looking up SID: lookup account NoSuchUserOrGroup: not found"
		if errMsg := err.Error(); errMsg != expected {
			t.Errorf("expected: %s, got: %s", expected, errMsg)
		}
	})
}

func TestUnixSocketWithOpts(t *testing.T) {
	socketPath := tempSocketPath(t)
	l, err := NewUnixSocketWithOpts(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	echoStr := "hello"
	runTest(t, socketPath, l, echoStr)
}

func TestNewUnixSocket(t *testing.T) {
	group := wellKnownAccountName(t, windows.WinBuiltinUsersSid)
	socketPath := filepath.Join(os.TempDir(), "test.sock")
	t.Logf("socketPath: %s, path length: %d", socketPath, len(socketPath))

	l, err := NewUnixSocket(socketPath, []string{group})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	runTest(t, socketPath, l, "hello")
}

func TestNewUnixSocketUnknownGroup(t *testing.T) {
	const group = "NoSuchUserOrGroup" // non-existing user or group
	socketPath := filepath.Join(os.TempDir(), "fail.sock")
	_, err := NewUnixSocket(socketPath, []string{group})
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}
