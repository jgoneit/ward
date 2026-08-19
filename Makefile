.PHONY: build test vet check clean

build:
	go build -o bin/ward ./cmd/ward

test:
	go test ./...

vet:
	go vet ./...

check: test vet

clean:
	go clean
