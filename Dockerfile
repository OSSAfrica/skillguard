FROM cgr.dev/chainguard/go@sha256:a29506323609aeee20bc963ea6d998bc76a6c05728358147e2e334d9d8a3c6f4 AS builder

ARG VERSION=dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X skillguard/cmd.Version=${VERSION}" -o skillguard .

FROM cgr.dev/chainguard/static@sha256:207a5673ab31ed83332e54ae33d0f1de4adb5984bd93b8309789889e7bf30ba6

COPY --from=builder /app/skillguard /skillguard

USER nonroot

ENTRYPOINT ["/skillguard"]
