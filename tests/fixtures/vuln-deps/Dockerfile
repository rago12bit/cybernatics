FROM ubuntu:18.04
USER root
ADD https://example.com/app.tar.gz /app/
RUN apt-get update && apt-get install -y curl
CMD ["/app/run"]
