.PHONY: all gen-proto build-node build-client build test clean

all: gen-proto build

gen-proto:
	protoc --proto_path=proto --go_out=. --go-grpc_out=. proto/directory.proto

build-node:
	set GOOS=windows GOARCH=amd64
	go build -o bin/trn-node cmd/node/main.go

build-client:
	set GOOS=windows GOARCH=amd64
	go build -o bin/trn-client cmd/client/main.go

build: build-node build-client

test:
	go test ./...

clean:
	rm -rf bin/ cert.pem key.pem
