build:
	go build -o bin/kerberos ./cmd/kerberos
	go build -o bin/client ./cmd/client
	go build -o bin/server ./cmd/server
	go build -o bin/kconfig ./cmd/kconfig

run-kerberos:
	CGO_CFLAGS="-Wno-return-local-addr" go run ./cmd/kerberos

run-client:
	go run ./cmd/client

run-server:
	go run ./cmd/server

run-asconfig:
	go run ./cmd/asconfig

run-tgsconfig:
	go run ./cmd/tgsconfig