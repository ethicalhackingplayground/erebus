package formatter

import (
	"time"

	jsoniter "github.com/json-iterator/go"
)

// JSON is a formatter for outputting json logs
type JSON struct{}

var _ Formatter = &JSON{}

var jsoniterCfg jsoniter.API

func init() {
	jsoniterCfg = jsoniter.Config{SortMapKeys: true}.Froze()
}

// Format formats the log event data into bytes
func (j *JSON) Format(event *LogEvent) ([]byte, error) {
	data := make(map[string]interface{})
	if lable, ok := event.Metadata["lable"]; ok {
		if lable != "" {
			data["level"] = lable
			delete(event.Metadata, "lable")
		}
	}
	for k, v := range event.Metadata {
		data[k] = v
	}
	data["msg"] = event.Message
	data["timestamp"] = time.Now().UTC().Format("2006-01-02T15:04:05-0700")
	return jsoniterCfg.Marshal(data)
}
