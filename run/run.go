package run

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"src/requests"
	"src/scan"
	"src/yamlconf"
	"sync"

	"github.com/projectdiscovery/gologger"
)

var (
	dirName string
	wg      = new(sync.WaitGroup)
	config  yamlconf.YamlConfig
)

// Run the erebus
func Scanner(parseBurp string, payload string, payloads string, burpCollab string, templates string, silent string, threads int, pattern string, paths string, status int, out string) {

	// Load the templates
	fi, err := os.Stat(templates)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}

	mode := fi.Mode()
	if mode.IsRegular() {
		if silent == "false" {
			gologger.Debug().Msgf("Loading Template [%s]", templates)
		}
		fmt.Println("")
	} else {
		// Validate the template directory
		dirName := yamlconf.ValidatePath(templates)

		files, err := ioutil.ReadDir(dirName)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		if silent == "false" {
			for _, t := range files {
				gologger.Debug().Msgf("Loading Template [%s]", dirName+t.Name())
			}
			fmt.Println("")
		}
	}

	if templates != "" && payloads == "" && payload == "" {

		if parseBurp != "" {

			if mode.IsDir() {
				// Valide the path
				dirName := yamlconf.ValidatePath(templates)
				files, err := ioutil.ReadDir(dirName)
				if err != nil {
					gologger.Error().Msg(err.Error())
				}

				for j := 0; j < len(files); j++ {
					template := dirName + files[j].Name()
					config := yamlconf.ReadTemplates(template)
					burpXML := requests.ParseBurpFile(parseBurp)

					hosts := make(chan string)

					// Use parallelism to speed up the processing
					for i := 0; i < threads; i++ {
						wg.Add(1)
						go func() {
							for url := range hosts {
								scan.ScanHostsWithTemplates(*config, wg, url, config.Request.Payloads, pattern, silent, templates, out)
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

				burpXML := requests.ParseBurpFile(parseBurp)
				config := yamlconf.ReadTemplates(templates)

				hosts := make(chan string)

				// Use parallelism to speed up the processing
				for i := 0; i < threads; i++ {
					wg.Add(1)
					go func() {
						for url := range hosts {
							scan.ScanHostsWithTemplates(*config, wg, url, config.Request.Payloads, pattern, silent, templates, out)
						}
						wg.Done()
					}()
				}

				for i := 0; i < len(burpXML.Item.Url); i++ {
					if config.Request.Parameters == true {
						u, err := url.Parse(burpXML.Item.Url[i])
						if err != nil {
							return
						}
						if len(u.Query()) > 0 {
							hosts <- burpXML.Item.Url[i]
						}
					} else {
						hosts <- burpXML.Item.Url[i]
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

			// Use parallelism to speed up the processing
			for i := 0; i < threads; i++ {
				wg.Add(1)
				go func() {
					for url := range hosts {
						scan.ScanHostsWithTemplates(*config, wg, url, payloadList, pattern, silent, templates, out)
					}
					wg.Done()
				}()
			}

			// Create the 'NewScanner' object and print each line from Stdin
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

		if templates == "" && payloads == "" && payload != "" {
			var payloadArray = []string{}
			hosts := make(chan string)

			payloadArray = append(payloadArray)

			// Use parallelism to speed up the processing
			for i := 0; i < threads; i++ {
				wg.Add(1)
				go func() {
					for host := range hosts {
						scan.ScanWithSinglePayload(wg, host, payloadArray, pattern, paths, silent, status, out)
					}
					wg.Done()
				}()
			}

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

		} else {
			var payloadArray = []string{}

			file, err := os.Open(payloads)
			if err != nil {
				gologger.Error().Msgf(err.Error())
			}
			pScanner := bufio.NewScanner(file)
			for pScanner.Scan() {
				payloadArray = append(payloadArray, pScanner.Text())
			}

			hosts := make(chan string)
			// Use parallelism to speed up the processing
			for i := 0; i < threads; i++ {
				wg.Add(1)
				go func() {
					for host := range hosts {
						scan.ScanWithSinglePayload(wg, host, payloadArray, pattern, paths, silent, status, out)
					}
					wg.Done()

				}()
			}
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
