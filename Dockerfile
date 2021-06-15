FROM golang:1.16-alpine
WORKDIR /p4
RUN apk add --no-cache libpcap-dev libc-dev gcc tcpdump
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY network/ network/
COPY mitm.go .
