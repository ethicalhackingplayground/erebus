package gologger

import (
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
)

var (
	lables = map[levels.Level]string{
		levels.LevelFatal:   "FTL",
		levels.LevelError:   "ERR",
		levels.LevelInfo:    "INF",
		levels.LevelWarning: "WRN",
		levels.LevelDebug:   "DBG",
		levels.LevelVerbose: "VER",
	}
	// DefaultLogger is the default logging instance
	DefaultLogger *Logger
)

func init() {
	DefaultLogger = &Logger{}
	DefaultLogger.SetMaxLevel(levels.LevelInfo)
	DefaultLogger.SetFormatter(formatter.NewCLI(false))
	DefaultLogger.SetWriter(writer.NewCLI())
}

// Logger is a logger for logging structured data in a beautfiul and fast manner.
type Logger struct {
	writer    writer.Writer
	maxLevel  levels.Level
	formatter formatter.Formatter
}

// Log logs a message to a logger instance
func (l *Logger) Log(event *Event) {
	if event.level > l.maxLevel {
		return
	}
	event.message = strings.TrimSuffix(event.message, "\n")
	data, err := l.formatter.Format(&formatter.LogEvent{
		Message:  event.message,
		Level:    event.level,
		Metadata: event.metadata,
	})
	if err != nil {
		return
	}
	l.writer.Write(data, event.level)

	if event.level == levels.LevelFatal {
		os.Exit(1)
	}
}

// SetMaxLevel sets the max logging level for logger
func (l *Logger) SetMaxLevel(level levels.Level) {
	l.maxLevel = level
}

// SetFormatter sets the formatter instance for a logger
func (l *Logger) SetFormatter(formatter formatter.Formatter) {
	l.formatter = formatter
}

// SetWriter sets the writer instance for a logger
func (l *Logger) SetWriter(writer writer.Writer) {
	l.writer = writer
}

// Event is a log event to be written with data
type Event struct {
	logger   *Logger
	level    levels.Level
	message  string
	metadata map[string]string
}

// Lable applies a custom lable on the log event
func (e *Event) Lable(lable string) *Event {
	e.metadata["lable"] = lable
	return e
}

// Str adds a string metadata item to the log
func (e *Event) Str(key, value string) *Event {
	e.metadata[key] = value
	return e
}

// Msg logs a message to the logger
func (e *Event) Msg(format string) {
	e.message = format
	e.logger.Log(e)
}

// Msgf logs a printf style message to the logger
func (e *Event) Msgf(format string, args ...interface{}) {
	e.message = fmt.Sprintf(format, args...)
	e.logger.Log(e)
}

// Info writes a info message on the screen with the default lable
func Info() *Event {
	level := levels.LevelInfo
	event := &Event{
		logger:   DefaultLogger,
		level:    level,
		metadata: make(map[string]string),
	}
	event.metadata["lable"] = lables[level]
	return event
}

// Warning writes a warning message on the screen with the default lable
func Warning() *Event {
	level := levels.LevelWarning
	event := &Event{
		logger:   DefaultLogger,
		level:    level,
		metadata: make(map[string]string),
	}
	event.metadata["lable"] = lables[level]
	return event
}

// Error writes a error message on the screen with the default lable
func Error() *Event {
	level := levels.LevelError
	event := &Event{
		logger:   DefaultLogger,
		level:    level,
		metadata: make(map[string]string),
	}
	event.metadata["lable"] = lables[level]
	return event
}

// Debug writes an error message on the screen with the default lable
func Debug() *Event {
	level := levels.LevelDebug
	event := &Event{
		logger:   DefaultLogger,
		level:    level,
		metadata: make(map[string]string),
	}
	event.metadata["lable"] = lables[level]
	return event
}

// Fatal exits the program if we encounter a fatal error
func Fatal() *Event {
	level := levels.LevelFatal
	event := &Event{
		logger:   DefaultLogger,
		level:    level,
		metadata: make(map[string]string),
	}
	event.metadata["lable"] = lables[level]
	return event
}

// Silent prints a string on stdout without any extra lables.
func Silent() *Event {
	level := levels.LevelSilent
	event := &Event{
		logger:   DefaultLogger,
		level:    level,
		metadata: make(map[string]string),
	}
	return event
}

// Print prints a string on stderr without any extra lables.
func Print() *Event {
	level := levels.LevelInfo
	event := &Event{
		logger:   DefaultLogger,
		level:    level,
		metadata: make(map[string]string),
	}
	return event
}

// Verbose prints a string only in verbose output mode.
func Verbose() *Event {
	level := levels.LevelVerbose
	event := &Event{
		logger:   DefaultLogger,
		level:    level,
		metadata: make(map[string]string),
	}
	event.metadata["lable"] = lables[level]
	return event
}

// Info writes a info message on the screen with the default lable
func (l *Logger) Info() *Event {
	level := levels.LevelInfo
	event := &Event{
		logger:   l,
		level:    level,
		metadata: make(map[string]string),
	}
	event.metadata["lable"] = lables[level]
	return event
}

// Warning writes a warning message on the screen with the default lable
func (l *Logger) Warning() *Event {
	level := levels.LevelWarning
	event := &Event{
		logger:   l,
		level:    level,
		metadata: make(map[string]string),
	}
	event.metadata["lable"] = lables[level]
	return event
}

// Error writes a error message on the screen with the default lable
func (l *Logger) Error() *Event {
	level := levels.LevelError
	event := &Event{
		logger:   l,
		level:    level,
		metadata: make(map[string]string),
	}
	event.metadata["lable"] = lables[level]
	return event
}

// Debug writes an error message on the screen with the default lable
func (l *Logger) Debug() *Event {
	level := levels.LevelDebug
	event := &Event{
		logger:   l,
		level:    level,
		metadata: make(map[string]string),
	}
	event.metadata["lable"] = lables[level]
	return event
}

// Fatal exits the program if we encounter a fatal error
func (l *Logger) Fatal() *Event {
	level := levels.LevelFatal
	event := &Event{
		logger:   l,
		level:    level,
		metadata: make(map[string]string),
	}
	event.metadata["lable"] = lables[level]
	return event
}

// Print prints a string on screen without any extra lables.
func (l *Logger) Print() *Event {
	level := levels.LevelSilent
	event := &Event{
		logger:   l,
		level:    level,
		metadata: make(map[string]string),
	}
	return event
}

// Verbose prints a string only in verbose output mode.
func (l *Logger) Verbose() *Event {
	level := levels.LevelVerbose
	event := &Event{
		logger:   l,
		level:    level,
		metadata: make(map[string]string),
	}
	event.metadata["lable"] = lables[level]
	return event
}
