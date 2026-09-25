# Checkov: infrastructure-as-code misconfiguration (Terraform, CloudFormation, Kubernetes, Dockerfile, ...).
FROM python:3.12-slim
RUN pip install --no-cache-dir checkov==3.3.19 && useradd -m -u 10001 scanner
USER 10001
ENV HOME=/tmp CKV_IGNORE_HIDDEN_DIRECTORIES=false BC_SKIP_MAPPING=TRUE CHECKOV_RUN_SCA_PACKAGE_SCAN=false
ENTRYPOINT ["checkov"]
