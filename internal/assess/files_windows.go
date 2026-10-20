package assess

import (
	"errors"
	"os"
)

func openInput(root *os.Root, name string) (*os.File, error) {
	info, err := root.Stat(name)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("input is not regular")
	}
	return root.Open(name)
}
