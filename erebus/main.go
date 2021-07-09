package main

import (
	"github.com/ethicalhackingplayground/erebus/erebus/banner"
	"github.com/ethicalhackingplayground/erebus/erebus/parse"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	// Setup our Ctrl+C handler
	SetupCloseHandler()

	// Display the banner
	banner.Display()

	// Parse the arguments
	parse.Scan()
}

// SetupCloseHandler creates a 'listener' on a new goroutine which will notify the
// program if it receives an interrupt from the OS. We then handle this by calling
// our clean up procedure and exiting the program.
func SetupCloseHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		os.Exit(0)
	}()
}
