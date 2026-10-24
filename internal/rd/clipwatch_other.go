//go:build !windows

package rd

import (
	"context"
	"errors"
	"io"
)

// WatchFiles is only needed on Windows.
func WatchFiles(context.Context, io.Writer) error {
	return errors.New("not available on this system")
}
