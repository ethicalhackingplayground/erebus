package detect

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/ethicalhackingplayground/erebus/erebus/yamlconf"

	"github.com/fatih/color"
	"github.com/gocolly/colly/v2"
	"github.com/projectdiscovery/gologger"
)

// Save the results to a file
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

// Detect vulnerabilities with the interception proxy
func DetectVulnerabilitiesWhileIntercepting(request *http.Request, payload string, templates string, config yamlconf.YamlConfig, silent bool, out string) {

	client := &http.Client{}

	//
	// Determine if the Cross-Site-Scripting check is a "GET"" Request
	//
	if request.Method == "GET" {
		// Parse the URL
		u, err := url.Parse(request.URL.String())
		if err != nil {
			return
		}

		// Fetch the URL Values
		qs := url.Values{}
		for param, _ := range u.Query() {
			qs.Set(param, payload)
		}
		u.RawQuery = qs.Encode()
		query, err := url.QueryUnescape(u.String())
		if err != nil {
			return
		}

		// Create a new Request
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
								normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
								medium := color.New(color.FgYellow, color.Bold).SprintFunc()
								low := color.New(color.FgGreen, color.Bold).SprintFunc()
								info := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								switch config.Template.Severity {
								case "critical":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "high":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "medium":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "low":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "info":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
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
							normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
							medium := color.New(color.FgYellow, color.Bold).SprintFunc()
							low := color.New(color.FgGreen, color.Bold).SprintFunc()
							info := color.New(color.FgBlue, color.Bold).SprintFunc()
							white := color.New(color.FgWhite, color.Bold).SprintFunc()
							green := color.New(color.FgGreen, color.Bold).SprintFunc()
							switch config.Template.Severity {
							case "critical":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(query), white(http.StatusText(resp.StatusCode)))
								break
							case "high":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(query), white(http.StatusText(resp.StatusCode)))
								break
							case "medium":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(query), white(http.StatusText(resp.StatusCode)))
								break
							case "low":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(query), white(http.StatusText(resp.StatusCode)))
								break
							case "info":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(query), white(http.StatusText(resp.StatusCode)))
								break
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
								normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
								medium := color.New(color.FgYellow, color.Bold).SprintFunc()
								low := color.New(color.FgGreen, color.Bold).SprintFunc()
								info := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								switch config.Template.Severity {
								case "critical":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "high":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "medium":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "low":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "info":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(query), white(http.StatusText(resp.StatusCode)))
									break
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
								normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
								medium := color.New(color.FgYellow, color.Bold).SprintFunc()
								low := color.New(color.FgGreen, color.Bold).SprintFunc()
								info := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								switch config.Template.Severity {
								case "critical":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "high":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "medium":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "low":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "info":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								}
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

		//
		// Determine if the Cross-Site-Scripting check is a "POST" Request
		//
	} else if request.Method == "POST" {

		// Use the r.PostForm.Get() method to retrieve the relevant data fields
		// from the r.PostForm map.
		qs := url.Values{}
		for key, _ := range request.Form {
			qs.Set(key, payload)
		}

		// Create a new Request
		resp, err := http.Post(request.URL.String(), request.Header.Get("Content-Type"), bytes.NewBuffer([]byte(qs.Encode())))
		if err != nil {
			return
		}
		if silent == false {
			if resp.StatusCode == 403 || resp.StatusCode == 401 {
				red := color.New(color.FgRed, color.Bold).SprintFunc()
				white := color.New(color.FgWhite, color.Bold).SprintFunc()
				fmt.Printf("[%s]  %s [%s]\n", red("WAF"), white(request.URL.String()), white(http.StatusText(resp.StatusCode)))
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
									WriteResults(out, request.URL.String())
								}

								red := color.New(color.FgRed, color.Bold).SprintFunc()
								normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
								medium := color.New(color.FgYellow, color.Bold).SprintFunc()
								low := color.New(color.FgGreen, color.Bold).SprintFunc()
								info := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								switch config.Template.Severity {
								case "critical":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "high":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "medium":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "low":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "info":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								}

							}
						} else {

							if silent == true {
								return
							}
							blue := color.New(color.FgBlue, color.Bold).SprintFunc()
							white := color.New(color.FgWhite, color.Bold).SprintFunc()
							fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(request.URL.String()), white(http.StatusText(resp.StatusCode)))
						}
					}

				} else {
					for j := 0; j < len(config.Response.Patterns); j++ {
						for i := 0; i < len(config.Response.Exclude); i++ {
							if strings.Contains(bodyStr, config.Response.Patterns[j]) &&
								strings.Contains(bodyStr, config.Response.Exclude[i]) == false {

								if resp.StatusCode == config.Response.StatusCode {

									if out != "" {
										WriteResults(out, request.URL.String())
									}

									red := color.New(color.FgRed, color.Bold).SprintFunc()
									normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
									medium := color.New(color.FgYellow, color.Bold).SprintFunc()
									low := color.New(color.FgGreen, color.Bold).SprintFunc()
									info := color.New(color.FgBlue, color.Bold).SprintFunc()
									white := color.New(color.FgWhite, color.Bold).SprintFunc()
									green := color.New(color.FgGreen, color.Bold).SprintFunc()
									switch config.Template.Severity {
									case "critical":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "high":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "medium":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "low":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "info":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
										break
									}
								}
							} else {

								if silent == true {
									return
								}
								blue := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(request.URL.String()), white(http.StatusText(resp.StatusCode)))
							}
						}
					}
				}
			} else {
				for i := 0; i < len(config.Response.Exclude); i++ {

					if strings.Contains(bodyStr, config.Response.Exclude[i]) == false {

						if resp.StatusCode == config.Response.StatusCode {

							if out != "" {
								WriteResults(out, request.URL.String())
							}

							red := color.New(color.FgRed, color.Bold).SprintFunc()
							normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
							medium := color.New(color.FgYellow, color.Bold).SprintFunc()
							low := color.New(color.FgGreen, color.Bold).SprintFunc()
							info := color.New(color.FgBlue, color.Bold).SprintFunc()
							white := color.New(color.FgWhite, color.Bold).SprintFunc()
							green := color.New(color.FgGreen, color.Bold).SprintFunc()
							switch config.Template.Severity {
							case "critical":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
								break
							case "high":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
								break
							case "medium":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
								break
							case "low":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
								break
							case "info":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
								break
							}
						}
					} else {

						if silent == true {
							return
						}
						blue := color.New(color.FgBlue, color.Bold).SprintFunc()
						white := color.New(color.FgWhite, color.Bold).SprintFunc()
						fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(request.URL.String()), white(http.StatusText(resp.StatusCode)))
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
									WriteResults(out, request.URL.String())
								}

								red := color.New(color.FgRed, color.Bold).SprintFunc()
								normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
								medium := color.New(color.FgYellow, color.Bold).SprintFunc()
								low := color.New(color.FgGreen, color.Bold).SprintFunc()
								info := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								switch config.Template.Severity {
								case "critical":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "high":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "medium":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "low":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "info":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								}
							}
						} else {

							if silent == true {
								return
							}
							blue := color.New(color.FgBlue, color.Bold).SprintFunc()
							white := color.New(color.FgWhite, color.Bold).SprintFunc()
							fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(request.URL.String()), white(http.StatusText(resp.StatusCode)))
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
									WriteResults(out, request.URL.String())
								}

								red := color.New(color.FgRed, color.Bold).SprintFunc()
								normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
								medium := color.New(color.FgYellow, color.Bold).SprintFunc()
								low := color.New(color.FgGreen, color.Bold).SprintFunc()
								info := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								switch config.Template.Severity {
								case "critical":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "high":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "medium":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "low":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "info":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(normal("FORM ")+request.URL.String()), white(http.StatusText(resp.StatusCode)))
									break
								}
							}
						}
					} else {

						if silent == true {
							return
						}
						blue := color.New(color.FgBlue, color.Bold).SprintFunc()
						white := color.New(color.FgWhite, color.Bold).SprintFunc()
						fmt.Printf("[%s] %s [%s]\n", blue("NOT VULN"), white(request.URL.String()), white(http.StatusText(resp.StatusCode)))
					}
				}
			}
		}
	}
}

// Detect vulnerabilities with the interception proxy
func DetectVulnerabilitiesWhileCrawling(request *colly.Request, payload string, templates string, config yamlconf.YamlConfig, silent bool, out string) {

	client := &http.Client{}

	//
	// Determine if the Cross-Site-Scripting check is a "GET"" Request
	//
	if request.Method == "GET" {
		// Parse the URL
		u, err := url.Parse(request.URL.String())
		if err != nil {
			return
		}

		// Fetch the URL Values
		qs := url.Values{}
		for param, _ := range u.Query() {
			qs.Set(param, payload)
		}
		u.RawQuery = qs.Encode()
		query, err := url.QueryUnescape(u.String())
		if err != nil {
			return
		}

		// Create a new Request
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
								normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
								medium := color.New(color.FgYellow, color.Bold).SprintFunc()
								low := color.New(color.FgGreen, color.Bold).SprintFunc()
								info := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								switch config.Template.Severity {
								case "critical":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "high":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "medium":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "low":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "info":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(query), white(http.StatusText(resp.StatusCode)))
									break
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
							normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
							medium := color.New(color.FgYellow, color.Bold).SprintFunc()
							low := color.New(color.FgGreen, color.Bold).SprintFunc()
							info := color.New(color.FgBlue, color.Bold).SprintFunc()
							white := color.New(color.FgWhite, color.Bold).SprintFunc()
							green := color.New(color.FgGreen, color.Bold).SprintFunc()
							switch config.Template.Severity {
							case "critical":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(query), white(http.StatusText(resp.StatusCode)))
								break
							case "high":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(query), white(http.StatusText(resp.StatusCode)))
								break
							case "medium":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(query), white(http.StatusText(resp.StatusCode)))
								break
							case "low":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(query), white(http.StatusText(resp.StatusCode)))
								break
							case "info":
								fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(query), white(http.StatusText(resp.StatusCode)))
								break
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
								normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
								medium := color.New(color.FgYellow, color.Bold).SprintFunc()
								low := color.New(color.FgGreen, color.Bold).SprintFunc()
								info := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								switch config.Template.Severity {
								case "critical":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "high":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "medium":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "low":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "info":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(query), white(http.StatusText(resp.StatusCode)))
									break
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
								normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
								medium := color.New(color.FgYellow, color.Bold).SprintFunc()
								low := color.New(color.FgGreen, color.Bold).SprintFunc()
								info := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								switch config.Template.Severity {
								case "critical":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "high":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "medium":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "low":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								case "info":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(query), white(http.StatusText(resp.StatusCode)))
									break
								}
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

// Detect vulnerabilities using the template engine.
func DetectVulnerabilityWithTemplate(payload string, templates string, host string, config yamlconf.YamlConfig, silent bool, out string, command string) {

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}

	if command != "" {
		// If command is specified then run it first
		cmd := exec.Command("/bin/bash", "-c", "echo "+host+" | "+command)
		cmdReader, _ := cmd.StdoutPipe()

		scanner := bufio.NewScanner(cmdReader)
		done := make(chan bool)
		go func() {
			for scanner.Scan() {
				cmdOutput := scanner.Text()

				// Parse the URL
				u, err := url.Parse(cmdOutput)
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
											normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
											medium := color.New(color.FgYellow, color.Bold).SprintFunc()
											low := color.New(color.FgGreen, color.Bold).SprintFunc()
											info := color.New(color.FgBlue, color.Bold).SprintFunc()
											white := color.New(color.FgWhite, color.Bold).SprintFunc()
											green := color.New(color.FgGreen, color.Bold).SprintFunc()
											switch config.Template.Severity {
											case "critical":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "high":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "medium":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "low":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "info":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											}
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
										normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
										medium := color.New(color.FgYellow, color.Bold).SprintFunc()
										low := color.New(color.FgGreen, color.Bold).SprintFunc()
										info := color.New(color.FgBlue, color.Bold).SprintFunc()
										white := color.New(color.FgWhite, color.Bold).SprintFunc()
										green := color.New(color.FgGreen, color.Bold).SprintFunc()
										switch config.Template.Severity {
										case "critical":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "high":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "medium":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "low":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "info":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										}
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
											normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
											medium := color.New(color.FgYellow, color.Bold).SprintFunc()
											low := color.New(color.FgGreen, color.Bold).SprintFunc()
											info := color.New(color.FgBlue, color.Bold).SprintFunc()
											white := color.New(color.FgWhite, color.Bold).SprintFunc()
											green := color.New(color.FgGreen, color.Bold).SprintFunc()
											switch config.Template.Severity {
											case "critical":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "high":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "medium":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "low":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "info":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											}
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
										normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
										medium := color.New(color.FgYellow, color.Bold).SprintFunc()
										low := color.New(color.FgGreen, color.Bold).SprintFunc()
										info := color.New(color.FgBlue, color.Bold).SprintFunc()
										white := color.New(color.FgWhite, color.Bold).SprintFunc()
										green := color.New(color.FgGreen, color.Bold).SprintFunc()
										switch config.Template.Severity {
										case "critical":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "high":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "medium":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "low":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "info":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										}
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
											normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
											medium := color.New(color.FgYellow, color.Bold).SprintFunc()
											low := color.New(color.FgGreen, color.Bold).SprintFunc()
											info := color.New(color.FgBlue, color.Bold).SprintFunc()
											white := color.New(color.FgWhite, color.Bold).SprintFunc()
											green := color.New(color.FgGreen, color.Bold).SprintFunc()
											switch config.Template.Severity {
											case "critical":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "high":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "medium":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "low":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "info":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
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
												normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
												medium := color.New(color.FgYellow, color.Bold).SprintFunc()
												low := color.New(color.FgGreen, color.Bold).SprintFunc()
												info := color.New(color.FgBlue, color.Bold).SprintFunc()
												white := color.New(color.FgWhite, color.Bold).SprintFunc()
												green := color.New(color.FgGreen, color.Bold).SprintFunc()
												switch config.Template.Severity {
												case "critical":
													fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
													break
												case "high":
													fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
													break
												case "medium":
													fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
													break
												case "low":
													fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
													break
												case "info":
													fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
													break
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
						} else {
							for i := 0; i < len(config.Response.Exclude); i++ {

								if strings.Contains(bodyStr, config.Response.Exclude[i]) == false {

									if resp.StatusCode == config.Response.StatusCode {

										if out != "" {
											WriteResults(out, u.String())
										}

										red := color.New(color.FgRed, color.Bold).SprintFunc()
										normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
										medium := color.New(color.FgYellow, color.Bold).SprintFunc()
										low := color.New(color.FgGreen, color.Bold).SprintFunc()
										info := color.New(color.FgBlue, color.Bold).SprintFunc()
										white := color.New(color.FgWhite, color.Bold).SprintFunc()
										green := color.New(color.FgGreen, color.Bold).SprintFunc()
										switch config.Template.Severity {
										case "critical":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "high":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "medium":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "low":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "info":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
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
											normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
											medium := color.New(color.FgYellow, color.Bold).SprintFunc()
											low := color.New(color.FgGreen, color.Bold).SprintFunc()
											info := color.New(color.FgBlue, color.Bold).SprintFunc()
											white := color.New(color.FgWhite, color.Bold).SprintFunc()
											green := color.New(color.FgGreen, color.Bold).SprintFunc()
											switch config.Template.Severity {
											case "critical":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "high":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "medium":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "low":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "info":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
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
											normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
											medium := color.New(color.FgYellow, color.Bold).SprintFunc()
											low := color.New(color.FgGreen, color.Bold).SprintFunc()
											info := color.New(color.FgBlue, color.Bold).SprintFunc()
											white := color.New(color.FgWhite, color.Bold).SprintFunc()
											green := color.New(color.FgGreen, color.Bold).SprintFunc()
											switch config.Template.Severity {
											case "critical":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "high":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "medium":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "low":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											case "info":
												fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
												break
											}
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
			done <- true

		}()
		cmd.Start()
		<-done
		cmd.Wait()
	} else {

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
									normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
									medium := color.New(color.FgYellow, color.Bold).SprintFunc()
									low := color.New(color.FgGreen, color.Bold).SprintFunc()
									info := color.New(color.FgBlue, color.Bold).SprintFunc()
									white := color.New(color.FgWhite, color.Bold).SprintFunc()
									green := color.New(color.FgGreen, color.Bold).SprintFunc()
									switch config.Template.Severity {
									case "critical":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "high":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "medium":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "low":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "info":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									}
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
										normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
										medium := color.New(color.FgYellow, color.Bold).SprintFunc()
										low := color.New(color.FgGreen, color.Bold).SprintFunc()
										info := color.New(color.FgBlue, color.Bold).SprintFunc()
										white := color.New(color.FgWhite, color.Bold).SprintFunc()
										green := color.New(color.FgGreen, color.Bold).SprintFunc()
										switch config.Template.Severity {
										case "critical":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "high":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "medium":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "low":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "info":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										}
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
								normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
								medium := color.New(color.FgYellow, color.Bold).SprintFunc()
								low := color.New(color.FgGreen, color.Bold).SprintFunc()
								info := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								switch config.Template.Severity {
								case "critical":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "high":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "medium":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "low":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "info":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								}
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
									normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
									medium := color.New(color.FgYellow, color.Bold).SprintFunc()
									low := color.New(color.FgGreen, color.Bold).SprintFunc()
									info := color.New(color.FgBlue, color.Bold).SprintFunc()
									white := color.New(color.FgWhite, color.Bold).SprintFunc()
									green := color.New(color.FgGreen, color.Bold).SprintFunc()
									switch config.Template.Severity {
									case "critical":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "high":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "medium":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "low":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "info":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									}
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
								normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
								medium := color.New(color.FgYellow, color.Bold).SprintFunc()
								low := color.New(color.FgGreen, color.Bold).SprintFunc()
								info := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								switch config.Template.Severity {
								case "critical":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "high":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "medium":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "low":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "info":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								}
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
									normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
									medium := color.New(color.FgYellow, color.Bold).SprintFunc()
									low := color.New(color.FgGreen, color.Bold).SprintFunc()
									info := color.New(color.FgBlue, color.Bold).SprintFunc()
									white := color.New(color.FgWhite, color.Bold).SprintFunc()
									green := color.New(color.FgGreen, color.Bold).SprintFunc()
									switch config.Template.Severity {
									case "critical":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "high":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "medium":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "low":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "info":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
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
										normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
										medium := color.New(color.FgYellow, color.Bold).SprintFunc()
										low := color.New(color.FgGreen, color.Bold).SprintFunc()
										info := color.New(color.FgBlue, color.Bold).SprintFunc()
										white := color.New(color.FgWhite, color.Bold).SprintFunc()
										green := color.New(color.FgGreen, color.Bold).SprintFunc()
										switch config.Template.Severity {
										case "critical":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "high":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "medium":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "low":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
										case "info":
											fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
											break
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
				} else {
					for i := 0; i < len(config.Response.Exclude); i++ {

						if strings.Contains(bodyStr, config.Response.Exclude[i]) == false {

							if resp.StatusCode == config.Response.StatusCode {

								if out != "" {
									WriteResults(out, u.String())
								}

								red := color.New(color.FgRed, color.Bold).SprintFunc()
								normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
								medium := color.New(color.FgYellow, color.Bold).SprintFunc()
								low := color.New(color.FgGreen, color.Bold).SprintFunc()
								info := color.New(color.FgBlue, color.Bold).SprintFunc()
								white := color.New(color.FgWhite, color.Bold).SprintFunc()
								green := color.New(color.FgGreen, color.Bold).SprintFunc()
								switch config.Template.Severity {
								case "critical":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "high":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "medium":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "low":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
								case "info":
									fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
									break
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
									normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
									medium := color.New(color.FgYellow, color.Bold).SprintFunc()
									low := color.New(color.FgGreen, color.Bold).SprintFunc()
									info := color.New(color.FgBlue, color.Bold).SprintFunc()
									white := color.New(color.FgWhite, color.Bold).SprintFunc()
									green := color.New(color.FgGreen, color.Bold).SprintFunc()
									switch config.Template.Severity {
									case "critical":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "high":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "medium":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "low":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "info":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
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
									normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
									medium := color.New(color.FgYellow, color.Bold).SprintFunc()
									low := color.New(color.FgGreen, color.Bold).SprintFunc()
									info := color.New(color.FgBlue, color.Bold).SprintFunc()
									white := color.New(color.FgWhite, color.Bold).SprintFunc()
									green := color.New(color.FgGreen, color.Bold).SprintFunc()
									switch config.Template.Severity {
									case "critical":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), red("critical"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "high":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), normal("high"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "medium":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), medium("medium"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "low":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), low("low"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									case "info":
										fmt.Printf("[%s] [%s] %s [%s]\n", green(templates), info("info"), white(u.String()), white(http.StatusText(resp.StatusCode)))
										break
									}
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
}

func Contains(item string, query []string) bool {
	for _, a := range query {
		if a == item {
			return true
		}
	}
	return false
}
