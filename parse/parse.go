package parse

import (
	"flag"
	"math/rand"
	"runtime"
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
	silent     string
	output     string
)

// Create the arguments used for erebus
func ParseArguments() {

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
	flag.StringVar(&silent, "silent", "", "silent (only show vulnerable urls)")
	// Parse the arguments
	flag.Parse()

	rand.Seed(time.Now().UnixNano())
	nCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(nCPU)
}
