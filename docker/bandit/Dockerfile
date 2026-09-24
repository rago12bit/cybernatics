FROM python:3.12-slim
RUN pip install --no-cache-dir bandit==1.7.10 && useradd -m -u 10001 scanner
USER 10001
ENTRYPOINT ["bandit"]
