.PHONY: doctor server cert test-unit capture-doctor

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
