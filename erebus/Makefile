# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
    
all: build
build:
		sudo $(GOBUILD) -v -ldflags="-extldflags=-static" -o "erebus" main.go
test: 
		sudo $(GOTEST) -v ./...
tidy:
		sudo $(GOMOD) tidy