FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o skillguard .

FROM cgr.dev/chainguard/static:latest

COPY --from=builder /app/skillguard /skillguard

ENTRYPOINT ["/skillguard"]
