package scan

import (
	"net/http"

	"github.com/ethicalhackingplayground/src/erebus/detect"
	"github.com/ethicalhackingplayground/src/erebus/yamlconf"

	"github.com/gocolly/colly/v2"
)

func InterceptAndScan(
	req *http.Request,
	payloads []string,
	templates string,
	config yamlconf.YamlConfig,
	silent bool,
	out string) {

	for _, payload := range payloads {

		// Find vulnerabilities
		detect.DetectVulnerabilitiesWhileIntercepting(req, payload, templates, config, silent, out)
	}

}

func CrawlAndScan(
	req *colly.Request,
	payloads []string,
	templates string,
	config yamlconf.YamlConfig,
	silent bool,
	out string) {

	for _, payload := range payloads {

		// Find vulnerabilities
		detect.DetectVulnerabilitiesWhileCrawling(req, payload, templates, config, silent, out)
	}

}

func ScanHostsWithTemplates(
	config yamlconf.YamlConfig,
	host string,
	payloads []string,
	silent bool,
	templates string,
	out string,
	command string,
	intercept bool) {

	for _, payload := range payloads {

		// Find vulnerabilities
		detect.DetectVulnerabilityWithTemplate(payload, templates, host, config, silent, out, command)
	}

}

func ScanBurpXmlWithTemplates(
	config yamlconf.YamlConfig,
	host string,
	payloads []string,
	silent bool,
	templates string,
	out string,
	command string) {

	for _, payload := range payloads {
		// Find vulnerabilities
		detect.DetectVulnerabilityWithTemplate(payload, templates, host, config, silent, out, command)
	}

}
