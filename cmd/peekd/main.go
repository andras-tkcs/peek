package main

import (
	"os"

	"github.com/andras-tkcs/peek/internal/peekd"
)

func main() {
	os.Exit(peekd.Run(os.Args[1:]))
}
