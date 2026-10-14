# gosec: Go SAST. It type-checks the code, so the image needs the Go toolchain. There is no network at run time:
# modules that are not vendored cannot be downloaded, and gosec then analyses only what it can load
# (see docs/adding-a-scanner.md).
FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0

FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d
COPY --from=build /go/bin/gosec /usr/local/bin/gosec
RUN adduser -D -u 10001 scanner
USER 10001
ENV HOME=/tmp GOCACHE=/tmp/gocache GOPATH=/tmp/go GOFLAGS=-mod=mod GOPROXY=off GOTOOLCHAIN=local GOTELEMETRY=off CGO_ENABLED=0
ENTRYPOINT ["gosec"]
