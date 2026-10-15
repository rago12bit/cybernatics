# Nuclei: the active DAST tier. The template library is baked in at build time, pinned to a release,
# so a campaign downloads nothing: the only traffic it sends is to the verified target, through the
# campaign's egress proxy. (The upstream image ships no templates; it fetched ~86 MB from GitHub on
# every run, outside the proxy.) Rebuild with a newer TEMPLATES to refresh it, as with Grype's
# database. Run with -duc (no update check) and -ni (no interactsh): core/dast/adapters/nuclei.py.
#
# The engine is built here from source rather than taken from projectdiscovery's image (THREAT-MODEL
# T10): the image and the release checksums are unsigned, but Go fetches the source from the module
# proxy and checks it against sum.golang.org, the public append-only log of every module version's
# hash. What still has to be trusted: the golang image (digest-pinned, unsigned) and the source.
# Go 1.26: nuclei v3.11.1 requires it. The image keeps upstream's layout (alpine, /usr/local/bin/nuclei, templates under /root).
FROM golang:1.26-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GONOSUMDB= GOPRIVATE= GOINSECURE= GOFLAGS=-trimpath
ARG NUCLEI_VERSION=3.11.1
RUN go install -ldflags "-s -w" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v${NUCLEI_VERSION}"

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
COPY --from=build /go/bin/nuclei /usr/local/bin/nuclei

ARG TEMPLATES=v10.5.0
RUN apk add --no-cache git \
 && git clone --depth 1 --branch "${TEMPLATES}" https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates \
 && rm -rf /root/nuclei-templates/.git \
 && apk del git \
 && nuclei -duc -tl -silent > /tmp/templates.txt \
 && test "$(wc -l < /tmp/templates.txt)" -gt 5000 \
 && rm /tmp/templates.txt

ENTRYPOINT ["nuclei"]
