FROM cgr.dev/chainguard/go@sha256:92fa6538c060088fb3aa7e87e4d4e916b7f58c6cdcb4aa25b16433e0f324dfbd AS builder

ARG VERSION=dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X skillguard/cmd.Version=${VERSION} -X skillguard/cmd.Distribution=docker" -o skillguard .

FROM cgr.dev/chainguard/static@sha256:599c3cd7597b84aa149c4282beecc8c6d4e1cb5c95dc8d982e70cd0a2a9147a2

COPY --from=builder /app/skillguard /skillguard

USER nonroot

ENTRYPOINT ["/skillguard"]
