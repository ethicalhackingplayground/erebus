package formatter

import (
	"bytes"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger/levels"
)

// CLI is a formatter for outputting CLI logs
type CLI struct {
	NoUseColors bool
	aurora      aurora.Aurora
}

var _ Formatter = &CLI{}

// NewCLI returns a new CLI based formatter
func NewCLI(noUseColors bool) *CLI {
	return &CLI{NoUseColors: noUseColors, aurora: aurora.NewAurora(!noUseColors)}
}

// Format formats the log event data into bytes
func (c *CLI) Format(event *LogEvent) ([]byte, error) {
	c.colorizeLable(event)

	buffer := &bytes.Buffer{}
	buffer.Grow(len(event.Message))

	lable, ok := event.Metadata["lable"]
	if lable != "" && ok {
		buffer.WriteRune('[')
		buffer.WriteString(lable)
		buffer.WriteRune(']')
		buffer.WriteRune(' ')
		delete(event.Metadata, "lable")
	}
	buffer.WriteString(event.Message)

	for k, v := range event.Metadata {
		buffer.WriteRune(' ')
		buffer.WriteString(c.colorizeKey(k))
		buffer.WriteRune('=')
		buffer.WriteString(v)
	}
	data := buffer.Bytes()
	return data, nil
}

// colorizeKey colorizes the metadata key if enabled
func (c *CLI) colorizeKey(key string) string {
	if c.NoUseColors {
		return key
	}
	return c.aurora.Bold(key).String()
}

// colorizeLable colorizes the lables if their exists one and colors are enabled
func (c *CLI) colorizeLable(event *LogEvent) {
	lable := event.Metadata["lable"]
	if lable == "" || c.NoUseColors {
		return
	}
	switch event.Level {
	case levels.LevelSilent:
		return
	case levels.LevelInfo, levels.LevelVerbose:
		event.Metadata["lable"] = c.aurora.Blue(lable).String()
	case levels.LevelFatal:
		event.Metadata["lable"] = c.aurora.Bold(aurora.Red(lable)).String()
	case levels.LevelError:
		event.Metadata["lable"] = c.aurora.Red(lable).String()
	case levels.LevelDebug:
		event.Metadata["lable"] = c.aurora.Magenta(lable).String()
	case levels.LevelWarning:
		event.Metadata["lable"] = c.aurora.Yellow(lable).String()
	}
}
