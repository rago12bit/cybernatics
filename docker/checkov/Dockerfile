# Checkov: infrastructure-as-code misconfiguration (Terraform, CloudFormation, Kubernetes, Dockerfile, ...).
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
RUN pip install --no-cache-dir checkov==3.3.19 && useradd -m -u 10001 scanner
USER 10001
ENV HOME=/tmp CKV_IGNORE_HIDDEN_DIRECTORIES=false BC_SKIP_MAPPING=TRUE CHECKOV_RUN_SCA_PACKAGE_SCAN=false
ENTRYPOINT ["checkov"]
