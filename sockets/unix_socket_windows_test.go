package sockets

import (
	"errors"
	"os/user"
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
	socketPath := tempSocketPath(t)

	l, err := NewUnixSocket(socketPath, []string{group})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	runTest(t, socketPath, l, "hello")
}

// TestNewUnixSocketWithOptsAbstract verifies that abstract Unix sockets behave
// correctly. Unlike filesystem-backed sockets, they must not create a socket
// file before or after the listener is closed.
func TestNewUnixSocketWithOptsAbstract(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	// Go documents "@" as a Linux-specific shorthand for abstract Unix sockets:
	//
	//   "On Linux, a Name beginning with '@' denotes an abstract socket address:
	//    the '@' is translated to a NUL byte when the address is passed to the
	//    kernel..."
	//
	// See https://pkg.go.dev/net@go1.27rc2#UnixAddr.
	//
	// Windows uses the native kernel representation (a leading NUL byte) for
	// abstract Unix sockets. Both forms are tested here to document Go's
	// platform-specific behavior.
	prefixes := []struct{ name, prefix string }{
		{name: "at_prefix", prefix: "@"},
		{name: "nul_prefix", prefix: "\x00"},
	}
	tests := []struct {
		name string
		opts []SockOption
	}{
		{
			name: "no options",
		},
		{
			name: "base permissions",
			opts: []SockOption{
				WithBasePermissions(),
			},
		},
		{
			name: "additional users and groups",
			opts: []SockOption{
				WithAdditionalUsersAndGroups([]string{currentUser.Username}),
			},
		},
	}

	for _, prefix := range prefixes {
		t.Run(prefix.name, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					socketPath := prefix.prefix + filepath.Base(tempSocketPath(t))
					l, err := NewUnixSocketWithOpts(socketPath, tc.opts...)
					if err == nil {
						_ = l.Close()
						t.Fatalf("expected abstract socket %q to be rejected", socketPath)
					}
					if !errors.Is(err, errors.ErrUnsupported) {
						t.Fatalf("expected unsupported error, got %v", err)
					}
				})
			}
		})
	}
}

func TestNewUnixSocketUnknownGroup(t *testing.T) {
	const group = "NoSuchUserOrGroup" // non-existing user or group
	socketPath := tempSocketPath(t)
	_, err := NewUnixSocket(socketPath, []string{group})
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}
