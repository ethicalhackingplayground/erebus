package global

import "sync"

var (
	dirName      string
	burpUrls     = make(chan string)
	yamlPayloads = make(chan string)
	payloadList  = make(chan string)
	hosts        = make(chan string)
	wg           sync.WaitGroup
)
