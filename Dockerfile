FROM cgr.dev/chainguard/go@sha256:cdd198f79e8bd05933cd1bf7113d404065edca90e45859bed16b41c57aeb853b AS builder

ARG VERSION=dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X skillguard/cmd.Version=${VERSION}" -o skillguard .

FROM cgr.dev/chainguard/static@sha256:77d8b8925dc27970ec2f48243f44c7a260d52c49cd778288e4ee97566e0cb75b

COPY --from=builder /app/skillguard /skillguard

USER nonroot

ENTRYPOINT ["/skillguard"]
