//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package sockets

import "syscall"

func maxListenerBacklog() int {
	return syscall.SOMAXCONN
}
