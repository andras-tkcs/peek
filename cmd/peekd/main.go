package main

import (
	"os"

	"github.com/privacyfence/peek/internal/peekd"
)

func main() {
	os.Exit(peekd.Run(os.Args[1:]))
}
