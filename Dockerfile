FROM cgr.dev/chainguard/go@sha256:a29506323609aeee20bc963ea6d998bc76a6c05728358147e2e334d9d8a3c6f4 AS builder

ARG VERSION=dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X skillguard/cmd.Version=${VERSION}" -o skillguard .

FROM cgr.dev/chainguard/static@sha256:24dd7ff8788fdfadda39eeeaefefb6d1cec6002a545935a5f7e017484053734f

COPY --from=builder /app/skillguard /skillguard

USER nonroot

ENTRYPOINT ["/skillguard"]
