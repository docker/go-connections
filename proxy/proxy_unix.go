//go:build !windows

package proxy

import "syscall"

// errConnReset is the platform-specific "connection reset by peer".
const errConnReset = syscall.ECONNRESET
