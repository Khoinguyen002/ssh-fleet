package power

import "os"

func execPID() int {
	return os.Getpid()
}
