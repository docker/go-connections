package proxy

import (
	"syscall"
)

// errConnReset is the platform-specific "connection reset by peer".
//
// https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2#wsaeconnreset
const errConnReset = syscall.WSAECONNRESET
