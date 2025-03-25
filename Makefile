GO      ?= go
BINDIR  := bin
PLAIN   := config.plain.txt
SEALED  := config.sealed.bin

.PHONY: all build seal run-kbs run-workload demo test test-ext bench plot clean docker-up docker-down

all: build

build:
	$(GO) build -o $(BINDIR)/kbs ./cmd/kbs
	$(GO) build -o $(BINDIR)/workload ./cmd/workload
	$(GO) build -o $(BINDIR)/seal ./cmd/seal

seal:
	$(GO) run ./cmd/seal -in $(PLAIN) -out $(SEALED)

run-kbs:
	$(GO) run ./cmd/kbs

run-workload: $(SEALED)
	KBS_URL=http://127.0.0.1:8080 SEALED_CONFIG=$(SEALED) $(GO) run ./cmd/workload

$(SEALED): $(PLAIN)
	$(GO) run ./cmd/seal -in $(PLAIN) -out $(SEALED)

demo: $(SEALED)
	./scripts/demo.sh

test:
	$(GO) test ./...

test-ext:
	CGO_ENABLED=1 $(GO) test -ldflags=-linkmode=external ./...

bench:
	$(GO) run ./cmd/bench -n 300

plot: bench
	python3 bench/plot.py

docker-up:
	docker compose up --build

docker-down:
	docker compose down -v

clean:
	rm -rf $(BINDIR) $(SEALED) bench/overhead.svg
