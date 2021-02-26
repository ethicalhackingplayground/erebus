package main

import (
	"flag"
	"os"
	"os/signal"
	"src/banner"
	"src/parse"
	"src/run"
	"strconv"
	"syscall"

	"github.com/projectdiscovery/gologger"
)

func main() {

	// Setup our Ctrl+C handler
	SetupCloseHandler()

	// Display the banner
	banner.Display()

	// Parse the arguments
	parse.ParseArguments()

	// Run the tool
	Execute()
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

func Execute() {

	// Check if these arguments are used
	if flag.Lookup("p").Value.String() == "" &&
		flag.Lookup("pL").Value.String() == "" &&
		flag.Lookup("t").Value.String() == "" {
		// Print the banner
		banner.Display()
		// Show the arguments
		flag.PrintDefaults()

	} else {

		parseBurp := flag.Lookup("burp-sitemap").Value.String()
		payload := flag.Lookup("p").Value.String()
		payloads := flag.Lookup("pL").Value.String()
		burpCollab := flag.Lookup("collab-payload").Value.String()
		templates := flag.Lookup("t").Value.String()
		silent := flag.Lookup("silent").Value.String()
		pattern := flag.Lookup("pattern").Value.String()
		paths := flag.Lookup("paths").Value.String()
		out := flag.Lookup("o").Value.String()

		threads, err := strconv.Atoi(flag.Lookup("c").Value.String())
		if err != nil {
			gologger.Error().Msg(err.Error())
			return
		}
		statusCode, err := strconv.Atoi(flag.Lookup("statusCode").Value.String())
		if err != nil {
			gologger.Error().Msg(err.Error())
			return
		}
		run.Scanner(parseBurp, payload, payloads, burpCollab, templates, silent, threads, pattern, paths, statusCode, out)
	}
}
