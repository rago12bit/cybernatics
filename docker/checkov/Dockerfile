# Checkov: infrastructure-as-code misconfiguration (Terraform, CloudFormation, Kubernetes, Dockerfile, ...).
#
# Checkov's wheel is checked against its PyPI provenance (PEP 740), signed through Sigstore when
# bridgecrewio/checkov's own workflow published it, before it is installed (THREAT-MODEL T10). This
# covers checkov itself; its dependencies are installed from PyPI as before, unverified.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS verify
ARG CHECKOV_VERSION=3.3.19
ARG PYPI_ATTESTATIONS_VERSION=0.0.30
RUN pip install --no-cache-dir "pypi-attestations==${PYPI_ATTESTATIONS_VERSION}" \
 && pip download --no-cache-dir --no-deps --only-binary=:all: "checkov==${CHECKOV_VERSION}" -d /wheels \
 && pypi-attestations verify pypi --repository https://github.com/bridgecrewio/checkov \
      "/wheels/checkov-${CHECKOV_VERSION}-py3-none-any.whl"

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ARG CHECKOV_VERSION=3.3.19
COPY --from=verify /wheels /wheels
RUN pip install --no-cache-dir "/wheels/checkov-${CHECKOV_VERSION}-py3-none-any.whl" && rm -rf /wheels \
 && useradd -m -u 10001 scanner
USER 10001
ENV HOME=/tmp CKV_IGNORE_HIDDEN_DIRECTORIES=false BC_SKIP_MAPPING=TRUE CHECKOV_RUN_SCA_PACKAGE_SCAN=false
ENTRYPOINT ["checkov"]
