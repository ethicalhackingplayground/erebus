package scan

import (
	"src/detect"
	"src/yamlconf"
	"sync"
)

func ScanHostsWithTemplates(
	config yamlconf.YamlConfig,
	wg *sync.WaitGroup,
	host string,
	payloads []string,
	pattern string,
	silent bool,
	templates string,
	out string) {

	for _, payload := range payloads {
		// Find vulnerabilities
		detect.DetectVulnerabilityWithTemplate(wg, payload, templates, host, config, silent, out)
	}

}

func ScanWithSinglePayload(
	wg *sync.WaitGroup,
	host string,
	payload []string,
	pattern string,
	paths string,
	silent bool,
	status int,
	out string) {

	// Use burp to parse file and find vulnerabilities
	detect.DetectVulnerabilityCustom(wg, host, payload[0], status, silent, paths, pattern, out)
}

func ScanWithMultiplePayloads(
	wg *sync.WaitGroup,
	host string,
	payloads []string,
	pattern string,
	paths string,
	silent bool,
	status int,
	out string) {

	for _, payload := range payloads {
		// Find vulnerabilities
		detect.DetectVulnerabilityCustom(wg, host, payload, status, silent, paths, pattern, out)
	}
}
