.PHONY: doctor server cert

doctor:
	./scripts/bh doctor

server:
	./scripts/bh server --config configs/server.toml

cert:
	./scripts/bh cert create --hostname localhost --hostname 127.0.0.1 --hostname ::1 --out local/tls
