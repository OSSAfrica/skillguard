//go:build !windows

package assess

import (
	"os"
	"syscall"
)

// Nonblocking open prevents hostile FIFOs from hanging assessment before Stat.
func openInput(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
