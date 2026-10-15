# Dockle: container image linter (CIS Docker benchmark). It reads an image archive (`docker save`), not source.
#
# Built here from source rather than run from its author's image (THREAT-MODEL T10): the image and
# the release checksums are unsigned, but Go fetches the source from the module proxy and checks it
# against sum.golang.org, the public append-only log of every module version's hash. What still has
# to be trusted: the golang image (digest-pinned, unsigned) and the source itself.
FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GONOSUMDB= GOPRIVATE= GOINSECURE= GOFLAGS=-trimpath
ARG DOCKLE_VERSION=0.4.15
RUN go install -ldflags "-s -w -X github.com/goodwithtech/dockle/pkg.version=${DOCKLE_VERSION}" \
      "github.com/goodwithtech/dockle/cmd/dockle@v${DOCKLE_VERSION}"

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
COPY --from=build /go/bin/dockle /usr/bin/dockle
USER 10001
ENTRYPOINT ["/usr/bin/dockle"]
