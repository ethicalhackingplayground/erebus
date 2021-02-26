package detect

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"src/yamlconf"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/projectdiscovery/gologger"
)

func WriteResults(filename string, result string) {
	f, err := os.OpenFile(filename,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	defer f.Close()
	if _, err := f.WriteString(result + "\n"); err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
}

func DetectVulnerabilityCustom(wg *sync.WaitGroup, host string, payload string, status int, silent bool, paths string, pattern string, out string) {

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}

	// Parse the URL
	u, err := url.Parse(host)
	if err != nil {
		return
	}

	if paths == "true" {

		// Create a new Request
		protocol := strings.Split(u.String(), ":")[0]
		domain := strings.Split(u.String(), "/")[2]
		req, err := http.NewRequest("GET", protocol+"://"+domain+"/"+payload, nil)
		if err != nil {
			return
		}

		resp, err := client.Do(req)
		if err != nil {
			return
		}
		if silent == false {
			if resp.StatusCode == 403 || resp.StatusCode == 401 {
				red := color.New(color.FgRed, color.Bold).SprintFunc()
				white := color.New(color.FgWhite, color.Bold).SprintFunc()
				fmt.Printf("[%s]  %s [%s]\n", red("WAF"), white(u.String()), white(http.StatusText(resp.StatusCode)))
				return
			}
		}
		bytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}

		bodyStr := string(bytes)

		if strings.Contains(bodyStr, pattern) {

			if resp.StatusCode == status {

				if out != "" {
					WriteResults(out, u.String())
				}
				red := color.New(color.FgRed, color.Bold).SprintFunc()
				white := color.New(color.FgWhite, color.Bold).SprintFunc()
				fmt.Printf("[%s] %s [%s]\n", red("VULN"), white(u.String()), white(http.StatusText(resp.StatusCode)))
			}
		} else {

			if silent == true {
				return
			}
			blue := color.New(color.FgBlue, color.Bold).SprintFunc()
			white := color.New(color.FgWhite, color.Bold).SprintFunc()
			fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(u.String()), white(http.StatusText(resp.StatusCode)))
		}
	} else {

		// Fetch the URL Values
		qs := url.Values{}

		for param, _ := range u.Query() {
			qs.Set(param, payload)
		}
		u.RawQuery = qs.Encode()

		// Create a new Request
		// Create a new Request
		query, err := url.QueryUnescape(u.String())
		if err != nil {
			return
		}
		req, err := http.NewRequest("GET", query, nil)
		if err != nil {
			return
		}

		resp, err := client.Do(req)
		if err != nil {
			return
		}

		bytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}

		bodyStr := string(bytes)
		if silent == false {
			if resp.StatusCode == 403 || resp.StatusCode == 401 {
				red := color.New(color.FgRed, color.Bold).SprintFunc()
				white := color.New(color.FgWhite, color.Bold).SprintFunc()
				fmt.Printf("[%s]  %s [%s]\n", red("WAF"), white(u.String()), white(http.StatusText(resp.StatusCode)))
				return
			}
		}
		if strings.Contains(bodyStr, pattern) {

			if resp.StatusCode == status {

				if out != "" {
					WriteResults(out, u.String())
				}
				red := color.New(color.FgRed, color.Bold).SprintFunc()
				white := color.New(color.FgWhite, color.Bold).SprintFunc()
				fmt.Printf("[%s] %s [%s]\n", red("VULN"), white(query), white(http.StatusText(resp.StatusCode)))
			}
		} else {

			if silent == true {
				return
			}
			blue := color.New(color.FgBlue, color.Bold).SprintFunc()
			white := color.New(color.FgWhite, color.Bold).SprintFunc()
			fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(query), white(http.StatusText(resp.StatusCode)))
		}
	}
}

func DetectVulnerabilityWithTemplate(wg *sync.WaitGroup, payload string, templates string, host string, config yamlconf.YamlConfig, silent bool, out string) {

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	if strings.Contains(payload, "{{burp-collab}}") {
		payload = strings.ReplaceAll(payload, "{{burp-collab}}", payload)
	}
	// Parse the URL
	u, err := url.Parse(host)
	if err != nil {
		return
	}
	if config.Request.Paths == "true" {

		// Create a new Request
		protocol := strings.Split(u.String(), ":")[0]
		domain := strings.Split(u.String(), "/")[2]
		req, err := http.NewRequest("GET", protocol+"://"+domain+"/"+payload, nil)
		if err != nil {
			return
		}

		resp, err := client.Do(req)
		if err != nil {
			return
		}
		if silent == false {
			if resp.StatusCode == 403 || resp.StatusCode == 401 {
				red := color.New(color.FgRed, color.Bold).SprintFunc()
				white := color.New(color.FgWhite, color.Bold).SprintFunc()
				fmt.Printf("[%s] %s [%s]\n", red("WAF"), white(u.String()), white(http.StatusText(resp.StatusCode)))
				return
			}
		}
		respBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}
		bodyStr := string(respBytes)
		if len(config.Response.Exclude) > 0 {
			if len(config.Response.Header) > 0 {
				hh := resp.Header.Get("Content-Type")
				if !Contains(hh, config.Response.Header) {

					for i := 0; i < len(config.Response.Exclude); i++ {

						if strings.Contains(bodyStr, config.Response.Exclude[i]) == false {

							if resp.StatusCode == config.Response.StatusCode {

								if out != "" {
									WriteResults(out, u.String())
								}

								red := color.New(color.FgRed, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("VULN"), white(u.String()), white(http.StatusText(resp.StatusCode)))
							}
						} else {

							if silent == true {
								return
							}
							blue := color.New(color.FgBlue, color.Bold).SprintFunc()
							white := color.New(color.FgWhite, color.Bold).SprintFunc()
							fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(u.String()), white(http.StatusText(resp.StatusCode)))
						}
					}

				} else {
					for j := 0; j < len(config.Response.Patterns); j++ {
						for i := 0; i < len(config.Response.Exclude); i++ {
							if strings.Contains(bodyStr, config.Response.Patterns[j]) &&
								strings.Contains(bodyStr, config.Response.Exclude[i]) == false {

								if resp.StatusCode == config.Response.StatusCode {

									if out != "" {
										WriteResults(out, u.String())
									}

									red := color.New(color.FgRed, color.Bold).SprintFunc()
									white := color.New(color.FgWhite, color.Bold).SprintFunc()
									green := color.New(color.FgGreen, color.Bold).SprintFunc()
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("VULN"), white(u.String()), white(http.StatusText(resp.StatusCode)))
								}
							} else {

								if silent == true {
									return
								}
								blue := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(u.String()), white(http.StatusText(resp.StatusCode)))
							}
						}
					}
				}
			} else {
				for i := 0; i < len(config.Response.Exclude); i++ {

					if strings.Contains(bodyStr, config.Response.Exclude[i]) == false {

						if resp.StatusCode == config.Response.StatusCode {

							if out != "" {
								WriteResults(out, u.String())
							}

							red := color.New(color.FgRed, color.Bold).SprintFunc()
							white := color.New(color.FgWhite, color.Bold).SprintFunc()
							green := color.New(color.FgGreen, color.Bold).SprintFunc()
							fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("VULN"), white(u.String()), white(http.StatusText(resp.StatusCode)))
						}
					} else {

						if silent == true {
							return
						}
						blue := color.New(color.FgBlue, color.Bold).SprintFunc()
						white := color.New(color.FgWhite, color.Bold).SprintFunc()
						fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(u.String()), white(http.StatusText(resp.StatusCode)))
					}
				}
			}
		} else {
			if len(config.Response.Patterns) == 0 {
				return
			}
			if len(config.Response.Header) > 0 {
				hh := resp.Header.Get("Content-Type")
				if !Contains(hh, config.Response.Header) {
					for i := 0; i < len(config.Response.Patterns); i++ {
						if strings.Contains(bodyStr, config.Response.Patterns[i]) {

							if resp.StatusCode == config.Response.StatusCode {

								if out != "" {
									WriteResults(out, u.String())
								}

								red := color.New(color.FgRed, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("VULN"), white(u.String()), white(http.StatusText(resp.StatusCode)))
							}
						} else {

							if silent == true {
								return
							}
							blue := color.New(color.FgBlue, color.Bold).SprintFunc()
							white := color.New(color.FgWhite, color.Bold).SprintFunc()
							fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(u.String()), white(http.StatusText(resp.StatusCode)))
						}
					}
				}
			} else {
				for i := 0; i < len(config.Response.Patterns); i++ {
					if strings.Contains(bodyStr, config.Response.Patterns[i]) {

						if resp.StatusCode == config.Response.StatusCode {

							if out != "" {
								WriteResults(out, u.String())
							}

							red := color.New(color.FgRed, color.Bold).SprintFunc()
							white := color.New(color.FgWhite, color.Bold).SprintFunc()
							green := color.New(color.FgGreen, color.Bold).SprintFunc()
							fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("VULN"), white(u.String()), white(http.StatusText(resp.StatusCode)))
						}
					} else {

						if silent == true {
							return
						}
						blue := color.New(color.FgBlue, color.Bold).SprintFunc()
						white := color.New(color.FgWhite, color.Bold).SprintFunc()
						fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(u.String()), white(http.StatusText(resp.StatusCode)))
					}
				}
			}
		}
	} else {

		// Fetch the URL Values
		qs := url.Values{}
		for param, _ := range u.Query() {
			qs.Set(param, payload)
		}
		u.RawQuery = qs.Encode()

		// Create a new Request
		query, err := url.QueryUnescape(u.String())
		if err != nil {
			return
		}
		req, err := http.NewRequest("GET", query, nil)
		if err != nil {
			return
		}

		resp, err := client.Do(req)
		if err != nil {
			return
		}
		if silent == false {
			if resp.StatusCode == 403 || resp.StatusCode == 401 {
				red := color.New(color.FgRed, color.Bold).SprintFunc()
				white := color.New(color.FgWhite, color.Bold).SprintFunc()
				fmt.Printf("[%s]  %s [%s]\n", red("WAF"), white(query), white(http.StatusText(resp.StatusCode)))
				return
			}
		}
		respBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}
		bodyStr := string(respBytes)
		if len(config.Response.Exclude) > 0 {
			if len(config.Response.Header) > 0 {
				hh := resp.Header.Get("Content-Type")
				if !Contains(hh, config.Response.Header) {

					for i := 0; i < len(config.Response.Exclude); i++ {

						if strings.Contains(bodyStr, config.Response.Exclude[i]) == false {

							if resp.StatusCode == config.Response.StatusCode {

								if out != "" {
									WriteResults(out, u.String())
								}

								red := color.New(color.FgRed, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("VULN"), white(query), white(http.StatusText(resp.StatusCode)))
							}
						} else {

							if silent == true {
								return
							}
							blue := color.New(color.FgBlue, color.Bold).SprintFunc()
							white := color.New(color.FgWhite, color.Bold).SprintFunc()
							fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(query), white(http.StatusText(resp.StatusCode)))
						}
					}

				} else {
					for j := 0; j < len(config.Response.Patterns); j++ {
						for i := 0; i < len(config.Response.Exclude); i++ {
							if strings.Contains(bodyStr, config.Response.Patterns[j]) &&
								strings.Contains(bodyStr, config.Response.Exclude[i]) == false {

								if resp.StatusCode == config.Response.StatusCode {

									if out != "" {
										WriteResults(out, u.String())
									}

									red := color.New(color.FgRed, color.Bold).SprintFunc()
									white := color.New(color.FgWhite, color.Bold).SprintFunc()
									green := color.New(color.FgGreen, color.Bold).SprintFunc()
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("VULN"), white(query), white(http.StatusText(resp.StatusCode)))
								}
							} else {

								if silent == true {
									return
								}
								blue := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(query), white(http.StatusText(resp.StatusCode)))
							}
						}
					}
				}
			} else {
				for i := 0; i < len(config.Response.Exclude); i++ {

					if strings.Contains(bodyStr, config.Response.Exclude[i]) == false {

						if resp.StatusCode == config.Response.StatusCode {

							if out != "" {
								WriteResults(out, u.String())
							}

							red := color.New(color.FgRed, color.Bold).SprintFunc()
							white := color.New(color.FgWhite, color.Bold).SprintFunc()
							green := color.New(color.FgGreen, color.Bold).SprintFunc()
							fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("VULN"), white(query), white(http.StatusText(resp.StatusCode)))
						}
					} else {

						if silent == true {
							return
						}
						blue := color.New(color.FgBlue, color.Bold).SprintFunc()
						white := color.New(color.FgWhite, color.Bold).SprintFunc()
						fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(query), white(http.StatusText(resp.StatusCode)))
					}
				}
			}
		} else {
			if len(config.Response.Patterns) == 0 {
				return
			}
			if len(config.Response.Header) > 0 {
				hh := resp.Header.Get("Content-Type")
				if !Contains(hh, config.Response.Header) {
					for i := 0; i < len(config.Response.Patterns); i++ {
						if strings.Contains(bodyStr, config.Response.Patterns[i]) {

							if resp.StatusCode == config.Response.StatusCode {

								if out != "" {
									WriteResults(out, u.String())
								}

								red := color.New(color.FgRed, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("VULN"), white(query), white(http.StatusText(resp.StatusCode)))
							}
						} else {

							if silent == true {
								return
							}
							blue := color.New(color.FgBlue, color.Bold).SprintFunc()
							white := color.New(color.FgWhite, color.Bold).SprintFunc()
							fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(query), white(http.StatusText(resp.StatusCode)))
						}
					}
				}

			} else {
				for i := 0; i < len(config.Response.Patterns); i++ {
					if strings.Contains(bodyStr, config.Response.Patterns[i]) {

						hh := resp.Header.Get("Content-Type")
						if !Contains(hh, config.Response.Header) {
							if resp.StatusCode == config.Response.StatusCode {

								if out != "" {
									WriteResults(out, u.String())
								}

								red := color.New(color.FgRed, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("VULN"), white(query), white(http.StatusText(resp.StatusCode)))
							}
						}
					} else {

						if silent == true {
							return
						}
						blue := color.New(color.FgBlue, color.Bold).SprintFunc()
						white := color.New(color.FgWhite, color.Bold).SprintFunc()
						fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(query), white(http.StatusText(resp.StatusCode)))
					}
				}
			}
		}
	}
}

func Contains(item string, query []string) bool {
	for _, a := range query {
		if a == item {
			return true
		}
	}
	return false
}
