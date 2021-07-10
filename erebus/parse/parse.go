package parse

import (
	"flag"
	"math/rand"
	"os"
	"os/exec"
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
	crawl := flag.Bool("crawl", false, "crawl through each intercepted request")
	updateTemplates := flag.Bool("ut", false, "Install or update the erebus-templates")
	silent := flag.Bool("silent", false, "silent (only show vulnerable urls)")
	// Parse the arguments
	flag.Parse()

	rand.Seed(time.Now().UnixNano())
	nCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(nCPU)

	// Check if the templates are used.
	if templates == "" && *updateTemplates == false {
		// Print the banner
		banner.Display()
		// Show the arguments
		flag.PrintDefaults()

		// No templates specified
		gologger.Error().Msg("Please specify a template")

	} else {

		if commandExists("git") && *updateTemplates == true {

			gologger.Info().Msg("Updating Erebus Templates\n")

			// If command is specified then run it first
			_, err := exec.Command("/bin/bash", "-c", "rm -rf erebus-templates ; git clone --verbose --progress  https://github.com/ethicalhackingplayground/erebus-templates").Output()
			if err != nil {
				// Display the output
				gologger.Error().Msg(err.Error())
				return
			}

			// Display the output
			gologger.Info().Msg("🔥 Erebus-templates Download 🔥")

		} else {

			if _, err := os.Stat("erebus-templates"); os.IsNotExist(err) {
				gologger.Error().Msg("Please, Download the erebus-templates or use -ut to install them\n")
				return
			}
		}

		// Run the scanner
		run.Scanner(parseBurp, templates, *silent, threads, output, tool, *interceptor, proxyPort, scope, *crawl, *ishttps, depth, *updateTemplates)
	}
}

// as util
func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
