FROM alpine:latest AS builder

ARG TLSS_VER=1.0.0
ENV DEBIAN_FRONTEND="noninteractive"

COPY ddr53-client.py requirements.txt /tmp
RUN set -ex \
   && apk add --no-cache --update --virtual .buid-deps \
        ca-certificates \
        tzdata \
        binutils \
        python3 \
        py3-pip \
        py3-requests  \
        py3-boto3 \
        py3-dnspython \
  && cd /tmp \
  && python3 -m venv /tmp/venv \
  && . /tmp/venv/bin/activate \
  && pip3 install --upgrade -r /tmp/requirements.txt \
  && pyinstaller -F --clean -n ddr53-client /tmp/ddr53-client.py


FROM alpine:latest
LABEL org.opencontainers.image.source=https://github.com/bz0qyz/ddr53-client
LABEL org.opencontainers.image.description="AWS Route53 Dynamic DNS Client"
LABEL org.opencontainers.image.licenses=Unlicense

ENV USER=ddr53-client
ENV UID=1010
ENV GROUP=ddr53-client
ENV USER_HOME=/home/ddr53-client

COPY --chmod=0755 docker-entrypoint.sh /usr/bin/docker-entrypoint.sh
COPY --from=builder /tmp/dist/ddr53-client /usr/local/bin/ddr53-client

RUN  set -ex; \
    echo Update alpine linux packages; \
    apk update && \
    apk upgrade --no-cache; \
    echo Install packages that will stay with the image; \
    apk add --no-cache --update --virtual .run-deps \
        bash \
        ca-certificates \
        tzdata \
        ; \
    echo Create a service account && \
    adduser -D  -h ${USER_HOME} -u ${UID} ${USER} ${GROUP} && \
    echo Create directories for configuration files && \
    ls -lR ${USER_HOME}

WORKDIR ${USER_HOME}
USER ${USER}

ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]
CMD ["/usr/local/bin/ddr53-client", "-d"]
