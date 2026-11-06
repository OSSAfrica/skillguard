FROM cgr.dev/chainguard/go@sha256:65e8b42e2c06a951df80725171337d9bdc8d3a2181d33cd2ef411a8a3d8873cc AS builder

ARG VERSION=dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X skillguard/cmd.Version=${VERSION} -X skillguard/cmd.Distribution=docker" -o skillguard .

FROM cgr.dev/chainguard/static@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde

COPY --from=builder /app/skillguard /skillguard

USER nonroot

ENTRYPOINT ["/skillguard"]
