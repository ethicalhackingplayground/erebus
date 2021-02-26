package requests

import (
	"encoding/xml"
	"io/ioutil"

	"github.com/projectdiscovery/gologger"
)

// the item struct, this contains our
// Type attribute, our urls,request
type Items struct {
	XMLName xml.Name `xml:"items"`
	Item    Item     `xml:"item"`
}

type Item struct {
	Url     []string `xml:"url"`
	Method  []string `xml:"method"`
	Request []string `xml:"request"`
}

func ParseBurpFile(xmlfile string) (conf *Items) {
	xmlFile, err := ioutil.ReadFile(xmlfile)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	// we initialize our Users array
	config := &Items{}
	// we unmarshal our byteArray which contains our
	// xmlFiles content into 'users' which we defined above
	err = xml.Unmarshal(xmlFile, &config)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	return config
}
