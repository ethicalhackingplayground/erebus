package run

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/ethicalhackingplayground/erebus/erebus/requests"
	"github.com/ethicalhackingplayground/erebus/erebus/scan"
	"github.com/ethicalhackingplayground/erebus/erebus/yamlconf"
	"github.com/fatih/color"
	"github.com/gocolly/colly/v2"
	"github.com/projectdiscovery/gologger"
	"gopkg.in/elazarl/goproxy.v1"
)

var (
	dirName string
	wg      = new(sync.WaitGroup)
	config  yamlconf.YamlConfig
)

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

// Run the erebus scanner based on the parsed arguments
func Scanner(parseBurp string, templates string, silent bool, threads int, out string, tool string, interceptor bool, proxyPort string, scope string, crawl bool, ishttps bool, depth int, updateTemplates bool) {

	// Load the templates
	fi, err := os.Stat(templates)
	if err != nil {
		return
	}

	mode := fi.Mode()
	if mode.IsRegular() {

		red := color.New(color.FgRed, color.Bold).SprintFunc()
		yellow := color.New(color.FgYellow, color.Bold).SprintFunc()
		normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
		medium := color.New(color.FgYellow, color.Bold).SprintFunc()
		low := color.New(color.FgGreen, color.Bold).SprintFunc()
		info := color.New(color.FgBlue, color.Bold).SprintFunc()
		white := color.New(color.FgWhite, color.Bold).SprintFunc()

		// Read and parse the payloads from the templates
		config := yamlconf.ReadTemplates(templates)

		switch config.Template.Severity {
		case "critical":
			fmt.Printf("[%s] %s (%s) [%s]",
				info(config.Template.Name),
				white(config.Template.Description), yellow(config.Template.Author), red(config.Template.Severity))
			break
		case "high":
			fmt.Printf("[%s] %s (%s) [%s]",
				info(config.Template.Name),
				white(config.Template.Description), yellow(config.Template.Author), normal(config.Template.Severity))
			break
		case "medium":
			fmt.Printf("[%s] %s (%s) [%s]",
				info(config.Template.Name),
				white(config.Template.Description), yellow(config.Template.Author), medium(config.Template.Severity))
			break
		case "low":
			fmt.Printf("[%s] %s (%s) [%s]",
				info(config.Template.Name),
				white(config.Template.Description), yellow(config.Template.Author), low(config.Template.Severity))
			break
		case "info":
			fmt.Printf("[%s] %s (%s) [%s]",
				info(config.Template.Name),
				white(config.Template.Description), yellow(config.Template.Author), info(config.Template.Severity))
			break
		}
		fmt.Println("\n")
	} else {

		if interceptor == true {
			gologger.Error().Msg("Erebus does not support multiple templates for interception.")
			return
		}

		// Valide the path
		dirName := yamlconf.ValidatePath(templates)
		files, err := ioutil.ReadDir(dirName)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}

		for j := 0; j < len(files); j++ {

			red := color.New(color.FgRed, color.Bold).SprintFunc()
			yellow := color.New(color.FgYellow, color.Bold).SprintFunc()
			normal := color.New(color.FgMagenta, color.Bold).SprintFunc()
			medium := color.New(color.FgYellow, color.Bold).SprintFunc()
			low := color.New(color.FgGreen, color.Bold).SprintFunc()
			info := color.New(color.FgBlue, color.Bold).SprintFunc()
			white := color.New(color.FgWhite, color.Bold).SprintFunc()

			if strings.HasSuffix(dirName+files[j].Name(), ".yaml") {
				// Read and parse the payloads from the templates
				config := yamlconf.ReadTemplates(dirName + files[j].Name())

				switch config.Template.Severity {
				case "critical":
					fmt.Printf("[%s] %s (%s) [%s]",
						info(config.Template.Name),
						white(config.Template.Description), yellow(config.Template.Author), red(config.Template.Severity))
					break
				case "high":
					fmt.Printf("[%s] %s (%s) [%s]",
						info(config.Template.Name),
						white(config.Template.Description), yellow(config.Template.Author), normal(config.Template.Severity))
					break
				case "medium":
					fmt.Printf("[%s] %s (%s) [%s]",
						info(config.Template.Name),
						white(config.Template.Description), yellow(config.Template.Author), medium(config.Template.Severity))
					break
				case "low":
					fmt.Printf("[%s] %s (%s) [%s]",
						info(config.Template.Name),
						white(config.Template.Description), yellow(config.Template.Author), low(config.Template.Severity))
					break
				case "info":
					fmt.Printf("[%s] %s (%s) [%s]",
						info(config.Template.Name),
						white(config.Template.Description), yellow(config.Template.Author), info(config.Template.Severity))
					break
				}
			}
		}
		fmt.Println("\n")
	}

	// Check the conditions to see if we are using the templates or single payloads
	if templates != "" {

		// Intercetor is turned on
		if interceptor == true {

			gologger.Info().Msgf("Proxy started on : %s\n\n", proxyPort)

			// Read and parse the payloads from the templates
			config := yamlconf.ReadTemplates(templates)
			payloadList := []string{}
			numPayloads := len(config.Request.Payloads)
			for i := 0; i < numPayloads; i++ {
				payloadList = append(payloadList, config.Request.Payloads[i])
			}

			// Crawling is enabled
			c := colly.NewCollector(
				colly.AllowedDomains(scope),
				colly.MaxDepth(depth),
			)

			// Visited URL(s) splice
			visited := []string{}

			// Config proxy.
			proxy := goproxy.NewProxyHttpServer()
			proxy.Verbose = false

			// Were only intercepting secure connections
			if ishttps == true {

				proxy.Tr = &http.Transport{

					// Config TLS cert verification.
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					Proxy:           http.ProxyFromEnvironment,
				}

				// Catch the Connect Request sent through to the proxy and make the proxy use "InsecureSkipVerify"
				/**proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile(scope))).
				HandleConnect(goproxy.AlwaysMitm)**/
				proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile(scope))).HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {

					proxy.Tr = &http.Transport{

						// Config TLS cert verification.
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
						Proxy:           http.ProxyFromEnvironment,
					}
					return goproxy.MitmConnect, host
				})
			}

			// Catch the request that is sent through the proxy server
			proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile(scope))).DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {

				if ishttps == true {
					ctx.Req.URL.Scheme = "https"
				}

				err := ctx.Req.ParseForm()
				if err != nil {
					gologger.Error().Msg(err.Error())
				}

				// Parse the form if the request is a POST/PUT
				if strings.Contains(ctx.Req.URL.String(), scope) {

					if config.Request.Parameters == true {
						// Check if the Url contains parameters
						params, _ := url.Parse(r.URL.String())

						// Only visit links once
						if len(params.Query()) > 0 &&
							!Contains(visited, ctx.Req.URL.String()) &&
							!Contains(config.Request.Exclude, ctx.Req.URL.String()) {

							if tool != "" {

								// If command is specified then run it first
								cmd := exec.Command("/bin/bash", "-c", "echo "+ctx.Req.URL.String()+" | "+tool)
								cmdReader, _ := cmd.StdoutPipe()

								scanner := bufio.NewScanner(cmdReader)

								for scanner.Scan() {

									// Keep track of visited URL(s)
									visited = append(visited, scanner.Text())

								}
								// Intercept the request and scan each parameter
								scan.InterceptAndScan(ctx.Req, payloadList, templates, *config, silent, out)

							} else {
								// Intercept the request and scan each parameter
								scan.InterceptAndScan(ctx.Req, payloadList, templates, *config, silent, out)
							}
						}

					} else {

						// Only visit links once
						if !Contains(visited, ctx.Req.URL.String()) &&
							!Contains(config.Request.Exclude, ctx.Req.URL.String()) {

							if tool != "" {

								// If command is specified then run it first
								cmd := exec.Command("/bin/bash", "-c", "echo "+ctx.Req.URL.String()+" | "+tool)
								cmdReader, _ := cmd.StdoutPipe()

								scanner := bufio.NewScanner(cmdReader)

								for scanner.Scan() {

									// Keep track of visited URL(s)
									visited = append(visited, scanner.Text())

								}
								// Intercept the request and scan each parameter
								scan.InterceptAndScan(ctx.Req, payloadList, templates, *config, silent, out)

							} else {
								// Intercept the request and scan each parameter
								scan.InterceptAndScan(ctx.Req, payloadList, templates, *config, silent, out)
							}
						}

					}

					// Start crawling through each link Visited
					if crawl == true {

						// Find and visit all links
						c.OnHTML("a[href]", func(e *colly.HTMLElement) {
							link := e.Attr("href")
							e.Request.Visit(e.Request.AbsoluteURL(link))
						})

						// The request of each link visisted
						c.OnRequest(func(r *colly.Request) {
							if config.Request.Parameters == true {

								// Check if the Url contains parameters
								params, _ := url.Parse(r.URL.String())
								if len(params.Query()) > 0 {

									// Only visit inscope items once
									if strings.ContainsAny(r.URL.String(), scope) &&
										!Contains(visited, r.URL.String()) &&
										!Contains(config.Request.Exclude, r.URL.String()) {

										if tool != "" {

											// If command is specified then run it first
											cmd := exec.Command("/bin/bash", "-c", "echo "+r.URL.String()+" | "+tool)
											cmdReader, _ := cmd.StdoutPipe()

											scanner := bufio.NewScanner(cmdReader)

											for scanner.Scan() {

												// Keep track of visited URL(s)
												visited = append(visited, scanner.Text())

											}
											// Crawl and scan
											scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)

										} else {
											// Crawl and scan
											scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)
										}
									}
								}

							} else {

								// Only visit inscope items once
								if strings.ContainsAny(r.URL.String(), scope) &&
									!Contains(visited, r.URL.String()) &&
									!Contains(config.Request.Exclude, r.URL.String()) {
									if tool != "" {

										// If command is specified then run it first
										cmd := exec.Command("/bin/bash", "-c", "echo "+r.URL.String()+" | "+tool)
										cmdReader, _ := cmd.StdoutPipe()

										scanner := bufio.NewScanner(cmdReader)

										for scanner.Scan() {

											// Keep track of visited URL(s)
											visited = append(visited, scanner.Text())

										}
										// Crawl and scan
										scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)

									} else {
										// Crawl and scan
										scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)
									}
								}
							}

						})

						c.Visit(ctx.Req.URL.String())
					}

				} else {

					if config.Request.Parameters == true {
						// Check if the Url contains parameters
						params, _ := url.Parse(r.URL.String())

						if len(params.Query()) > 0 &&
							!Contains(visited, r.URL.String()) &&
							!Contains(config.Request.Exclude, r.URL.String()) {
							if tool != "" {

								// If command is specified then run it first
								cmd := exec.Command("/bin/bash", "-c", "echo "+ctx.Req.URL.String()+" | "+tool)
								cmdReader, _ := cmd.StdoutPipe()

								scanner := bufio.NewScanner(cmdReader)

								for scanner.Scan() {

									// Keep track of visited URL(s)
									visited = append(visited, scanner.Text())

								}
								// Intercept the request and scan each parameter
								scan.InterceptAndScan(ctx.Req, payloadList, templates, *config, silent, out)

							} else {
								// Intercept the request and scan each parameter
								scan.InterceptAndScan(ctx.Req, payloadList, templates, *config, silent, out)
							}
						}

					} else {

						// Only visit links once
						if !Contains(visited, r.URL.String()) {

							if tool != "" {

								// If command is specified then run it first
								cmd := exec.Command("/bin/bash", "-c", "echo "+ctx.Req.URL.String()+" | "+tool)
								cmdReader, _ := cmd.StdoutPipe()

								scanner := bufio.NewScanner(cmdReader)

								for scanner.Scan() {

									// Keep track of visited URL(s)
									visited = append(visited, scanner.Text())

								}
								// Intercept the request and scan each parameter
								scan.InterceptAndScan(ctx.Req, payloadList, templates, *config, silent, out)

							} else {
								// Intercept the request and scan each parameter
								scan.InterceptAndScan(ctx.Req, payloadList, templates, *config, silent, out)
							}
						}
					}

					// Start crawling through each link Visited
					if crawl == true {

						// Find and visit all links
						c.OnHTML("a[href]", func(e *colly.HTMLElement) {
							link := e.Attr("href")
							e.Request.Visit(e.Request.AbsoluteURL(link))
						})

						// The request of each link visisted
						c.OnRequest(func(r *colly.Request) {
							if config.Request.Parameters == true {

								// Check if the Url contains parameters
								params, _ := url.Parse(r.URL.String())
								if len(params.Query()) > 0 &&
									!Contains(visited, r.URL.String()) &&
									!Contains(config.Request.Exclude, r.URL.String()) {

									if tool != "" {

										// If command is specified then run it first
										cmd := exec.Command("/bin/bash", "-c", "echo "+r.URL.String()+" | "+tool)
										cmdReader, _ := cmd.StdoutPipe()

										scanner := bufio.NewScanner(cmdReader)

										for scanner.Scan() {

											// Keep track of visited URL(s)
											visited = append(visited, scanner.Text())

										}
										// Crawl and scan
										scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)

									} else {
										// Crawl and scan
										scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)
									}
								}

							} else {

								// Only visit links once
								if !Contains(visited, r.URL.String()) &&
									!Contains(config.Request.Exclude, r.URL.String()) {

									if tool != "" {

										// If command is specified then run it first
										cmd := exec.Command("/bin/bash", "-c", "echo "+r.URL.String()+" | "+tool)
										cmdReader, _ := cmd.StdoutPipe()

										scanner := bufio.NewScanner(cmdReader)

										for scanner.Scan() {

											// Keep track of visited URL(s)
											visited = append(visited, scanner.Text())

										}
										// Crawl and scan
										scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)

									} else {
										// Crawl and scan
										scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)
									}
								}

							}

						})

						c.Visit(ctx.Req.URL.String())
					}
				}

				return r, nil
			})

			// Add handlers to respHandlers
			http.ListenAndServe(":"+proxyPort, proxy)

		} else {

			// Crawling is enabled
			c := colly.NewCollector(
				colly.AllowedDomains(scope),
				colly.MaxDepth(depth),
			)

			// The visited links
			visited := []string{}

			if parseBurp != "" {

				// Load the templates
				fi, err := os.Stat(templates)
				if err != nil {
					return
				}

				mode := fi.Mode()

				if mode.IsDir() {

					// Valide the path
					dirName := yamlconf.ValidatePath(templates)
					files, err := ioutil.ReadDir(dirName)
					if err != nil {
						gologger.Error().Msg(err.Error())
					}

					for j := 0; j < len(files); j++ {
						template := dirName + files[j].Name()

						burpXML := requests.ParseBurpFile(parseBurp)
						hosts := make(chan string)

						if strings.HasSuffix(template, ".yaml") {
							config := yamlconf.ReadTemplates(template)

							if crawl == true {

								payloadList := []string{}

								// Find and visit all links
								c.OnHTML("a[href]", func(e *colly.HTMLElement) {
									link := e.Attr("href")
									e.Request.Visit(e.Request.AbsoluteURL(link))
								})

								// The request of each link visisted
								c.OnRequest(func(r *colly.Request) {
									if config.Request.Parameters == true {

										// Check if the Url contains parameters
										params, _ := url.Parse(r.URL.String())
										if len(params.Query()) > 0 {

											// Only visit inscope items once
											if strings.ContainsAny(r.URL.String(), scope) &&
												!Contains(visited, r.URL.String()) &&
												!Contains(config.Request.Exclude, r.URL.String()) {

												if tool != "" {

													// If command is specified then run it first
													cmd := exec.Command("/bin/bash", "-c", "echo "+r.URL.String()+" | "+tool)
													cmdReader, _ := cmd.StdoutPipe()

													scanner := bufio.NewScanner(cmdReader)

													for scanner.Scan() {

														// Keep track of visited URL(s)
														visited = append(visited, scanner.Text())

													}
													// Crawl and scan
													scan.CrawlAndScan(r, payloadList, template, *config, silent, out)

												} else {
													// Crawl and scan
													scan.CrawlAndScan(r, payloadList, template, *config, silent, out)
												}
											}
										}

									} else {

										// Only visit inscope items once
										if strings.ContainsAny(r.URL.String(), scope) &&
											!Contains(visited, r.URL.String()) &&
											!Contains(config.Request.Exclude, r.URL.String()) {
											if tool != "" {

												// If command is specified then run it first
												cmd := exec.Command("/bin/bash", "-c", "echo "+r.URL.String()+" | "+tool)
												cmdReader, _ := cmd.StdoutPipe()

												scanner := bufio.NewScanner(cmdReader)

												for scanner.Scan() {

													// Keep track of visited URL(s)
													visited = append(visited, scanner.Text())

												}
												// Crawl and scan
												scan.CrawlAndScan(r, payloadList, template, *config, silent, out)

											} else {
												// Crawl and scan
												scan.CrawlAndScan(r, payloadList, template, *config, silent, out)
											}
										}
									}

								})

							}
							// Use parallelism to speed up the processing
							for i := 0; i < threads; i++ {
								wg.Add(1)
								go func() {
									for url := range hosts {
										scan.ScanBurpXmlWithTemplates(*config, url, config.Request.Payloads, silent, template, out, tool)
										if crawl == true {
											c.Visit(url)
										}
									}
									wg.Done()

								}()
							}

							for i := 0; i < len(burpXML.Item.Url); i++ {
								hosts <- burpXML.Item.Url[i]
							}
							close(hosts)
							wg.Wait()
						}
					}

				} else {

					burpXML := requests.ParseBurpFile(parseBurp)
					config := yamlconf.ReadTemplates(templates)

					// Define the hosts channel
					hosts := make(chan string)

					if crawl == true {

						payloadList := []string{}

						// Find and visit all links
						c.OnHTML("a[href]", func(e *colly.HTMLElement) {
							link := e.Attr("href")
							e.Request.Visit(e.Request.AbsoluteURL(link))
						})

						// The request of each link visisted
						c.OnRequest(func(r *colly.Request) {
							if config.Request.Parameters == true {

								// Check if the Url contains parameters
								params, _ := url.Parse(r.URL.String())
								if len(params.Query()) > 0 {

									// Only visit inscope items once
									if strings.ContainsAny(r.URL.String(), scope) &&
										!Contains(visited, r.URL.String()) &&
										!Contains(config.Request.Exclude, r.URL.String()) {

										if tool != "" {

											// If command is specified then run it first
											cmd := exec.Command("/bin/bash", "-c", "echo "+r.URL.String()+" | "+tool)
											cmdReader, _ := cmd.StdoutPipe()

											scanner := bufio.NewScanner(cmdReader)

											for scanner.Scan() {

												// Keep track of visited URL(s)
												visited = append(visited, scanner.Text())

											}
											// Crawl and scan
											scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)

										} else {
											// Crawl and scan
											scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)
										}
									}
								}

							} else {

								// Only visit inscope items once
								if strings.ContainsAny(r.URL.String(), scope) &&
									!Contains(visited, r.URL.String()) &&
									!Contains(config.Request.Exclude, r.URL.String()) {
									if tool != "" {

										// If command is specified then run it first
										cmd := exec.Command("/bin/bash", "-c", "echo "+r.URL.String()+" | "+tool)
										cmdReader, _ := cmd.StdoutPipe()

										scanner := bufio.NewScanner(cmdReader)

										for scanner.Scan() {

											// Keep track of visited URL(s)
											visited = append(visited, scanner.Text())

										}
										// Crawl and scan
										scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)

									} else {
										// Crawl and scan
										scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)
									}
								}
							}

						})

					}

					// Use parallelism to speed up the processing
					for i := 0; i < threads; i++ {
						wg.Add(1)
						go func() {
							for url := range hosts {
								// Scan using burps XML file
								scan.ScanBurpXmlWithTemplates(*config, url, config.Request.Payloads, silent, templates, out, tool)
								if crawl == true {
									c.Visit(url)
								}
							}
							wg.Done()
						}()
					}

					for i := 0; i < len(burpXML.Item.Url); i++ {
						hosts <- burpXML.Item.Url[i]
					}
					close(hosts)
					wg.Wait()
				}
			} else {

				// Load the templates
				fi, err := os.Stat(templates)
				if err != nil {
					return
				}

				mode := fi.Mode()
				if mode.IsDir() {

					// Valide the path
					dirName := yamlconf.ValidatePath(templates)
					files, err := ioutil.ReadDir(dirName)
					if err != nil {
						gologger.Error().Msg(err.Error())
					}

					for j := 0; j < len(files); j++ {

						// Read and parse the payloads from the templates
						template := dirName + files[j].Name()

						payloadList := []string{}
						hosts := make(chan string)

						if strings.HasSuffix(template, ".yaml") {
							config := yamlconf.ReadTemplates(template)
							numPayloads := len(config.Request.Payloads)
							for i := 0; i < numPayloads; i++ {
								payloadList = append(payloadList, config.Request.Payloads[i])
							}

							if crawl == true {
								// Find and visit all links
								c.OnHTML("a[href]", func(e *colly.HTMLElement) {
									link := e.Attr("href")
									e.Request.Visit(e.Request.AbsoluteURL(link))
								})

								// The request of each link visisted
								c.OnRequest(func(r *colly.Request) {
									if config.Request.Parameters == true {

										// Check if the Url contains parameters
										params, _ := url.Parse(r.URL.String())
										if len(params.Query()) > 0 {

											// Only visit inscope items once
											if strings.ContainsAny(r.URL.String(), scope) &&
												!Contains(visited, r.URL.String()) &&
												!Contains(config.Request.Exclude, r.URL.String()) {

												if tool != "" {

													// If command is specified then run it first
													cmd := exec.Command("/bin/bash", "-c", "echo "+r.URL.String()+" | "+tool)
													cmdReader, _ := cmd.StdoutPipe()

													scanner := bufio.NewScanner(cmdReader)

													for scanner.Scan() {

														// Keep track of visited URL(s)
														visited = append(visited, scanner.Text())

													}
													// Crawl and scan
													scan.CrawlAndScan(r, payloadList, template, *config, silent, out)

												} else {
													// Crawl and scan
													scan.CrawlAndScan(r, payloadList, template, *config, silent, out)
												}
											}
										}

									} else {

										// Only visit inscope items once
										if strings.ContainsAny(r.URL.String(), scope) &&
											!Contains(visited, r.URL.String()) &&
											!Contains(config.Request.Exclude, r.URL.String()) {
											if tool != "" {

												// If command is specified then run it first
												cmd := exec.Command("/bin/bash", "-c", "echo "+r.URL.String()+" | "+tool)
												cmdReader, _ := cmd.StdoutPipe()

												scanner := bufio.NewScanner(cmdReader)

												for scanner.Scan() {

													// Keep track of visited URL(s)
													visited = append(visited, scanner.Text())

												}
												// Crawl and scan
												scan.CrawlAndScan(r, payloadList, template, *config, silent, out)

											} else {
												// Crawl and scan
												scan.CrawlAndScan(r, payloadList, template, *config, silent, out)
											}
										}
									}

								})

							}
							// Use parallelism to speed up the processing
							for i := 0; i < threads; i++ {
								wg.Add(1)
								go func() {
									for url := range hosts {
										scan.ScanHostsWithTemplates(*config, url, payloadList, silent, template, out, tool, interceptor)
										if crawl == true {
											c.Visit(url)
										}
									}
									wg.Done()
								}()
							}
						}

						// Iterate over Stdin and parse the parameters to test.
						uScanner := bufio.NewScanner(os.Stdin)
						for uScanner.Scan() {

							if config.Request.Parameters == true {
								u, err := url.Parse(uScanner.Text())
								if err != nil {
									return
								}
								if len(u.Query()) > 0 {
									hosts <- uScanner.Text()
								}
							} else {
								hosts <- uScanner.Text()
							}
						}
						close(hosts)
						wg.Wait()
					}
				} else {
					config := yamlconf.ReadTemplates(templates)
					payloadList := []string{}
					hosts := make(chan string)
					numPayloads := len(config.Request.Payloads)
					for i := 0; i < numPayloads; i++ {
						payloadList = append(payloadList, config.Request.Payloads[i])
					}

					if crawl == true {

						// Find and visit all links
						c.OnHTML("a[href]", func(e *colly.HTMLElement) {
							link := e.Attr("href")
							e.Request.Visit(e.Request.AbsoluteURL(link))
						})

						// The request of each link visisted
						c.OnRequest(func(r *colly.Request) {
							if config.Request.Parameters == true {

								// Check if the Url contains parameters
								params, _ := url.Parse(r.URL.String())
								if len(params.Query()) > 0 {

									// Only visit inscope items once
									if strings.ContainsAny(r.URL.String(), scope) &&
										!Contains(visited, r.URL.String()) &&
										!Contains(config.Request.Exclude, r.URL.String()) {

										if tool != "" {

											// If command is specified then run it first
											cmd := exec.Command("/bin/bash", "-c", "echo "+r.URL.String()+" | "+tool)
											cmdReader, _ := cmd.StdoutPipe()

											scanner := bufio.NewScanner(cmdReader)

											for scanner.Scan() {

												// Keep track of visited URL(s)
												visited = append(visited, scanner.Text())

											}
											// Crawl and scan
											scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)

										} else {
											// Crawl and scan
											scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)
										}
									}
								}

							} else {

								// Only visit inscope items once
								if strings.ContainsAny(r.URL.String(), scope) &&
									!Contains(visited, r.URL.String()) &&
									!Contains(config.Request.Exclude, r.URL.String()) {
									if tool != "" {

										// If command is specified then run it first
										cmd := exec.Command("/bin/bash", "-c", "echo "+r.URL.String()+" | "+tool)
										cmdReader, _ := cmd.StdoutPipe()

										scanner := bufio.NewScanner(cmdReader)

										for scanner.Scan() {

											// Keep track of visited URL(s)
											visited = append(visited, scanner.Text())

										}
										// Crawl and scan
										scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)

									} else {
										// Crawl and scan
										scan.CrawlAndScan(r, payloadList, templates, *config, silent, out)
									}
								}
							}

						})

					}

					// Use parallelism to speed up the processing
					for i := 0; i < threads; i++ {
						wg.Add(1)
						go func() {
							for url := range hosts {
								scan.ScanHostsWithTemplates(*config, url, payloadList, silent, templates, out, tool, interceptor)
								if crawl == true {
									c.Visit(url)
								}
							}
							wg.Done()
						}()
					}

					// Iterate over Stdin and parse the parameters to test.
					uScanner := bufio.NewScanner(os.Stdin)
					for uScanner.Scan() {

						if config.Request.Parameters == true {
							u, err := url.Parse(uScanner.Text())
							if err != nil {
								return
							}
							if len(u.Query()) > 0 {
								hosts <- uScanner.Text()
							}
						} else {
							hosts <- uScanner.Text()
						}
					}
					close(hosts)
					wg.Wait()
				}
			}
		}
	}
}

// Reverse the string
func Reverse(s string) (result string) {
	for _, v := range s {
		result = string(v) + result
	}
	return
}

// Checks if item "e" is in the splice
func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
