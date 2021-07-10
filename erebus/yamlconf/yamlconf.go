package yamlconf

import (
	"io/ioutil"
	"strings"

	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v2"
)

// Yaml Contruct
type YamlConfig struct {
	Template struct {
		Name        string `yaml:"name"`
		Severity    string `yaml:"severity"`
		Author      string `yaml:"author"`
		Description string `yaml:"description"`
	}

	Request struct {
		Payloads   []string `yaml:"payloads"`
		Paths      string   `yaml:"paths"`
		Parameters bool     `yaml:"parameters"`
		Exclude    []string `yaml:"exclude"`
	}
	Response struct {
		StatusCode int      `yaml:"statusCode"`
		Patterns   []string `yaml:"patterns"`
		Exclude    []string `yaml:"exclude"`
		Header     []string `yaml:"header"`
	}
}

// read the templates directory and return the file
func ReadTemplates(templates string) (conf *YamlConfig) {
	file, err := ioutil.ReadFile(templates)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	config := &YamlConfig{}
	err = yaml.Unmarshal(file, &config)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	return config
}

// validate the templates dir path
func ValidatePath(templates string) (fixedPath string) {
	var dirName = ""
	if strings.HasSuffix(templates, "/") {
		dirName = templates
	} else {
		dirName = templates + "/"
	}
	return dirName
}
