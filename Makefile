build:
	go build -o bin/kerberos ./cmd/kerberos
	go build -o bin/client ./cmd/client
	go build -o bin/server ./cmd/server
	go build -o bin/kconfig ./cmd/kconfig

run-kerberos:
	CGO_CFLAGS="-Wno-return-local-addr" go run ./cmd/kerberos

run-client:
	CGO_CFLAGS="-Wno-return-local-addr" go run ./cmd/client $(SERVERIP) $(CMD)

run-service:
	CGO_CFLAGS="-Wno-return-local-addr" go run ./cmd/service $(ID) $(SERVICEIP) $(SERVICEPORT)

run-asconfig:
	CGO_CFLAGS="-Wno-return-local-addr" go run ./cmd/asconfig $(CMD)

run-tgsconfig:
	CGO_CFLAGS="-Wno-return-local-addr" go run ./cmd/tgsconfig $(TGSNAME) $(CMD)