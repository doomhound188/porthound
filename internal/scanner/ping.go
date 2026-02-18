package scanner

import (
	"os/exec"
	"runtime"
)

func PingWorker(id int, hosts <-chan string, results chan<- string) {
	for host := range hosts {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("ping", "-n", "2", "-w", "1000", host)
		} else {
			cmd = exec.Command("ping", "-c", "2", "-W", "2", host)
		}

		if err := cmd.Run(); err == nil {
			results <- host
		} else {
			results <- ""
		}
	}
}
