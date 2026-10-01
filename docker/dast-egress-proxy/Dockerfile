# The scope-enforcing egress proxy every DAST campaign runner's traffic must go through (Week 49
# task 2, plan §22.4). `core/dast/proxy.py` is pure stdlib asyncio -- no scanner tooling, no DB
# driver, no credentials of any kind baked into this image, since it sits on a compromised-scanner's
# network path by design and has nothing in it worth stealing.
FROM python:3.12-slim
RUN useradd -m -u 10003 bulwark-proxy
WORKDIR /app
COPY core/__init__.py ./core/__init__.py
COPY core/dast/__init__.py core/dast/proxy.py ./core/dast/
USER bulwark-proxy
ENTRYPOINT ["python", "-m", "core.dast.proxy"]
