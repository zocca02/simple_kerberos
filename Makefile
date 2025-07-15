build:
	go build -o bin/kerberos ./cmd/kerberos
	go build -o bin/client ./cmd/client
	go build -o bin/server ./cmd/server

run-kerberos:
	go run ./cmd/kerberos

run-client:
	go run ./cmd/client

run-server:
	go run ./cmd/server