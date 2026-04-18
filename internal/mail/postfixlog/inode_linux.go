//go:build linux

package postfixlog

import (
	"os"
	"syscall"
)

func inodeOS(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return uint64(fi.ModTime().UnixNano())
}
