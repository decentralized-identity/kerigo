package version

import "fmt"

func Code() string {
	return fmt.Sprintf("%x%x", 1, 0)
}
