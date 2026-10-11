.PHONY: all build test clean

all: build test

build:
	@mkdir -p bin
	GOPROXY=off go build -buildvcs=false -o bin/peerlink-control ./cmd/peerlink-control
	GOPROXY=off go build -buildvcs=false -o bin/peerlink-relay ./cmd/peerlink-relay
	GOPROXY=off go build -buildvcs=false -o bin/peerlinkd ./cmd/peerlinkd
	GOPROXY=off go build -buildvcs=false -o bin/peerlink ./cmd/peerlink
	@echo "Tüm ikili dosyalar bin/ dizininde oluşturuldu:"
	@ls -lh bin/

test:
	GOPROXY=off go test -v ./...

clean:
	rm -rf bin/
