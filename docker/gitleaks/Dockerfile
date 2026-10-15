# Gitleaks (MIT): secret detection. Built here from source rather than run from its author's image
# (THREAT-MODEL T10): the image is unsigned and so are the release checksums, but Go fetches the
# source from the module proxy and checks it against sum.golang.org, the public append-only log of
# every module version's hash -- so the code compiled is the code anyone else gets for that version,
# and a change to it would be visible in that log. What still has to be trusted: the golang image
# (a Docker Official Image, digest-pinned and unsigned) and the source itself.
FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GONOSUMDB= GOPRIVATE= GOINSECURE= GOFLAGS=-trimpath
ARG GITLEAKS_VERSION=8.21.0
RUN go install -ldflags "-s -w -X github.com/zricethezav/gitleaks/v8/cmd.Version=v${GITLEAKS_VERSION}" \
      "github.com/zricethezav/gitleaks/v8@v${GITLEAKS_VERSION}"

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
COPY --from=build /go/bin/gitleaks /usr/bin/gitleaks
USER 10001
ENTRYPOINT ["gitleaks"]
