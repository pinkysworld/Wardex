# ── Wardex — Developer Makefile ────────────────────────
.PHONY: build run test lint fmt check clean release dev admin fuzz bench doc release-acceptance

# ── Build ──
build:
	cargo build

release:
	cargo build --release

check:
	cargo check

# ── Run ──
run:
	cargo run

dev: build admin
	cargo run

# ── Test ──
test:
	cargo test

test-verbose:
	cargo test -- --nocapture

fuzz:
	cd fuzz && cargo +nightly fuzz run fuzz_pipeline -- -max_total_time=60

bench:
	cargo bench

# ── Lint / Format ──
lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt --all
	cd admin-console && npx eslint --fix src/

fmt-check:
	cargo fmt --all -- --check

# ── Admin Console ──
admin:
	cd admin-console && npm ci && npm run build

admin-dev:
	cd admin-console && npm run dev

admin-test:
	cd admin-console && npm test

admin-e2e:
	cd admin-console && npx playwright test

# ── Docker ──
docker-build:
	docker build -t wardex .

docker-run:
	docker compose up -d

docker-stop:
	docker compose down

# ── Documentation ──
doc:
	cargo doc --no-deps --open

# ── Clean ──
clean:
	cargo clean
	rm -rf admin-console/node_modules admin-console/output

# ── CI convenience ──
ci: fmt-check lint test admin-test

release-acceptance:
	bash ./scripts/release_acceptance.sh
