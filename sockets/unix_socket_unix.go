//go:build !windows
// +build !windows

package sockets

import "syscall"

func umask(newmask int) (oldmask int) {
	return syscall.Umask(0777)
}
