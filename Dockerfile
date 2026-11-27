FROM cgr.dev/chainguard/go@sha256:d5eb532c64db43c555c9fbf644628aac2690dcbfd07ac8b2bae97a7c66d085fb AS builder

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
