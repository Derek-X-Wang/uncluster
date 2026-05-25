package ca

import (
	"fmt"
	"os"
)

// loosePerm is returned when a file has overly permissive access controls.
type loosePerm struct {
	path string
	mode os.FileMode // 0 on Windows (mode bits not applicable)
}

func (e *loosePerm) Error() string {
	if e.mode != 0 {
		return fmt.Sprintf("ca: %s has mode %#o with group/world bits set; refusing (must be 0600)", e.path, e.mode)
	}
	return fmt.Sprintf("ca: %s has loose permissions (accessible to non-admin accounts); refusing", e.path)
}
