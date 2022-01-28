

build: generate
	go build .

PHONY: generate
generate:
	go generate ./...