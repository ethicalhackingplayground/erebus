package parse

import (
	"flag"
	"math/rand"
	"runtime"
	"time"

	"github.com/ethicalhackingplayground/erebus/erebus/banner"
	"github.com/ethicalhackingplayground/erebus/erebus/run"

	"github.com/projectdiscovery/gologger"
)

var (
	proxyPort string
	tool      string
	threads   int
	templates string
	parseBurp string
	output    string
	scope     string
	depth     int
)

// Run the Scanner
func Scan() {

	flag.IntVar(&threads, "c", 100, "the number of concurrent requsts")
	flag.StringVar(&templates, "t", "", "use the templates with all our yaml rules instead")
	flag.StringVar(&tool, "tc", "qsreplace", "Use other tools by executing an os command")
	flag.StringVar(&parseBurp, "burp-sitemap", "", "scan burp xml sitemap (without base64 decoded)")
	flag.StringVar(&output, "o", "", "output results to a file")
	flag.StringVar(&scope, "scope", "", "the scope for the proxy intercetor")
	flag.StringVar(&proxyPort, "p", "8080", "the port on which the interception proxy will listen on")
	flag.IntVar(&depth, "depth", 5, "the crawl depth")
	interceptor := flag.Bool("interceptor", false, "intercept the requests through the proxy and test each parameter")
	ishttps := flag.Bool("secure", false, "determaines if the connection is secure or not")
	crawl := flag.Bool("crawl", true, "crawl through each intercepted request")

	silent := flag.Bool("silent", false, "silent (only show vulnerable urls)")
	// Parse the arguments
	flag.Parse()

	rand.Seed(time.Now().UnixNano())
	nCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(nCPU)

	// Check if the templates are used.
	if templates == "" {
		// Print the banner
		banner.Display()
		// Show the arguments
		flag.PrintDefaults()

		// No templates specified
		gologger.Error().Msg("Please specify a template")

	} else {
		// Run the scanner
		run.Scanner(parseBurp, templates, *silent, threads, output, tool, *interceptor, proxyPort, scope, *crawl, *ishttps, depth)
	}
}
