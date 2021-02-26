package parse

import (
	"flag"
	"math/rand"
	"runtime"
	"src/banner"
	"src/run"
	"time"
)

var (
	threads    int
	templates  string
	parseBurp  string
	burpCollab string
	payload    string
	payloads   string
	statusCode int
	pattern    string
	paths      string
	output     string
)

// Run the Scanner
func Scan() {

	flag.IntVar(&threads, "c", 100, "the number of concurrent requsts")
	flag.StringVar(&templates, "t", "", "use the templates with all our yaml rules instead")
	flag.StringVar(&parseBurp, "burp-sitemap", "", "scan burp xml sitemap (without base64 decoded)")
	flag.StringVar(&burpCollab, "collab-payload", "", "use the burp collaborator for other types of testing")
	flag.StringVar(&payload, "p", "", "the payload to be used")
	flag.StringVar(&payloads, "pL", "", "the list of payloads to be used")
	flag.IntVar(&statusCode, "statusCode", 200, "filter by status codes")
	flag.StringVar(&pattern, "pattern", "", "match the response with some string")
	flag.StringVar(&paths, "paths", "false", "test payloads in the paths")
	flag.StringVar(&output, "o", "", "output results to a file")
	silent := flag.Bool("silent", false, "silent (only show vulnerable urls)")
	// Parse the arguments
	flag.Parse()

	rand.Seed(time.Now().UnixNano())
	nCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(nCPU)

	// Check if these arguments are used
	if payload == "" &&
		payloads == "" &&
		templates == "" {
		// Print the banner
		banner.Display()
		// Show the arguments
		flag.PrintDefaults()

	} else {
		run.Scanner(parseBurp, payload, payloads, burpCollab, templates, *silent, threads, pattern, paths, statusCode, output)
	}
}
