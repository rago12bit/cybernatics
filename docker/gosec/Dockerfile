# gosec: Go SAST. It type-checks the code, so the image needs the Go toolchain. There is no network at run time:
# modules that are not vendored cannot be downloaded, and gosec then analyses only what it can load
# (see docs/adding-a-scanner.md).
FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build
RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0

FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59
COPY --from=build /go/bin/gosec /usr/local/bin/gosec
RUN adduser -D -u 10001 scanner
USER 10001
ENV HOME=/tmp GOCACHE=/tmp/gocache GOPATH=/tmp/go GOFLAGS=-mod=mod GOPROXY=off GOTOOLCHAIN=local GOTELEMETRY=off CGO_ENABLED=0
ENTRYPOINT ["gosec"]
