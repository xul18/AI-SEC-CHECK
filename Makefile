.PHONY: build build-static build-linux build-darwin clean run test tidy package

BINARY=ai-sec-check.exe
VERSION=v1.0.0
LDFLAGS=-ldflags "-X ai-sec-check/internal/options.version=$(VERSION) -s -w"

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/cli

build-static:
	$env:CGO_ENABLED="0"; go build $(LDFLAGS) -o $(BINARY) ./cmd/cli

build-linux:
	$env:CGO_ENABLED="0"; $env:GOOS="linux"; $env:GOARCH="amd64"; go build $(LDFLAGS) -o ai-sec-check-linux-amd64 ./cmd/cli

build-darwin:
	$env:CGO_ENABLED="0"; $env:GOOS="darwin"; $env:GOARCH="arm64"; go build $(LDFLAGS) -o ai-sec-check-darwin-arm64 ./cmd/cli

build-debug:
	go build -o $(BINARY) ./cmd/cli

clean:
	del /f $(BINARY) 2>nul || true
	del /f ai-sec-check-static.exe 2>nul || true
	del /f ai-sec-check-linux-amd64 2>nul || true
	del /f ai-sec-check-darwin-arm64 2>nul || true

run: build
	.\$(BINARY) webserver --server 127.0.0.1:8088

scan: build
	.\$(BINARY) scan -t $(TARGET)

test:
	go test ./...

tidy:
	go mod tidy

package: build-static
	if exist dist rmdir /s /q dist
	mkdir dist\ai-sec-check
	copy $(BINARY) dist\ai-sec-check\
	xcopy configs dist\ai-sec-check\configs\ /E /I /Y
	xcopy data dist\ai-sec-check\data\ /E /I /Y
	copy start.bat dist\ai-sec-check\
	copy stop.bat dist\ai-sec-check\
	copy install.bat dist\ai-sec-check\
