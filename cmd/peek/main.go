package main

import (
	"os"

	"github.com/andras-tkcs/peek/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
