.PHONY: run build test vet fmt

# Run the API against a local Postgres, bootstrapping admin + demo accounts.
# For the full stack (Postgres included) use `docker compose up` from the repo root.
run:
	DATABASE_URL="postgres://afrashodan:afrashodan@localhost:5432/afrashodan?sslmode=disable" \
	JWT_SECRET=dev-secret ADMIN_USER=admin ADMIN_PASSWORD=admin12345 \
	DEMO_USER=demo DEMO_PASSWORD=demo12345 AFRASHODAN_SEED=data/sample.nessus \
	go run .

build:
	go build -o ../bin/afrashodan .

vet:
	go vet ./...

fmt:
	gofmt -w .

test:
	go test ./...
