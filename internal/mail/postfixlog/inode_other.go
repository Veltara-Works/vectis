//go:build !linux

package postfixlog

import "os"

func inodeOS(fi os.FileInfo) uint64 {
	return uint64(fi.ModTime().UnixNano())
}
