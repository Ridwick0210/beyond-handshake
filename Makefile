.PHONY: doctor server cert test-unit capture-doctor go-client test-go-client go-tls-client test-go-tls-client

doctor:
	./scripts/bh doctor

server:
	./scripts/bh server --config configs/server.toml

cert:
	./scripts/bh cert create --hostname localhost --hostname 127.0.0.1 --hostname ::1 --out local/tls

test-unit:
	.venv/bin/python -m unittest discover -s tests -v

capture-doctor:
	./scripts/bh capture doctor

go-client:
	mkdir -p local/bin
	cd clients/go_stdlib && go build -trimpath -o ../../local/bin/bh-go-client .

test-go-client:
	cd clients/go_stdlib && go test ./...

go-tls-client:
	mkdir -p local/bin
	cd clients/go_tls_client && go build -trimpath -o ../../local/bin/bh-go-tls-client .

test-go-tls-client:
	cd clients/go_tls_client && go test ./...
