package main

import (
	"os"

	"github.com/sv222/ai-guard-k8s/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
