# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.1 AS builder
ARG TARGETOS TARGETARCH
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o tlsproxy

FROM alpine:3
RUN apk add --no-cache ca-certificates
WORKDIR /root
COPY --from=builder /app/tlsproxy .
EXPOSE 443
# certificates are cached in /root/certs, mount a volume there to keep them
CMD ["/root/tlsproxy"]
