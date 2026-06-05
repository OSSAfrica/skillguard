FROM cgr.dev/chainguard/go@sha256:8333b6b6cae0251842b38d5a578d5a5230d73f9a8d9da377c32db53fa0d97b3a AS builder

ARG VERSION=dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X skillguard/cmd.Version=${VERSION}" -o skillguard .

FROM cgr.dev/chainguard/static@sha256:d6d54da1c5bf5d9cecb231786adca86934607763067c8d7d9d22057abe6d5dbc

COPY --from=builder /app/skillguard /skillguard

USER nonroot

ENTRYPOINT ["/skillguard"]
