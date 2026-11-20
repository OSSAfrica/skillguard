FROM cgr.dev/chainguard/go@sha256:92fa6538c060088fb3aa7e87e4d4e916b7f58c6cdcb4aa25b16433e0f324dfbd AS builder

ARG VERSION=dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X skillguard/cmd.Version=${VERSION} -X skillguard/cmd.Distribution=docker" -o skillguard .

FROM cgr.dev/chainguard/static@sha256:8658e9eaeb2294fa0e49b0667f7d66b4e21fa7690b8d2a4c30cd1d013ceb9eb7

COPY --from=builder /app/skillguard /skillguard

USER nonroot

ENTRYPOINT ["/skillguard"]
