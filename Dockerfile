FROM alpine:latest

ENV USER ddr53-client
ENV UID 1010
ENV GROUP ddr53-client
ENV USER_HOME /home/ddr53-client

COPY --chmod=0755 docker-entrypoint.sh /usr/bin/docker-entrypoint.sh
COPY --chmod=0755 ddr53-client.py /usr/bin/ddr53-client.py

RUN  set -ex; \
    echo Update alpine linux packages; \
    apk update && \
    apk upgrade --no-cache; \
    echo Install packages that will stay with the image; \
    apk add --no-cache --update --virtual .run-deps \
        bash \
        ca-certificates \
        tzdata \
        python3 \
        py3-pip \
        py3-requests  \
        py3-boto3 \
        py3-dnspython \
        ; \
    echo Create a service account && \
    adduser -D  -h ${USER_HOME} -u ${UID} ${USER} ${GROUP} && \
    echo Create directories for configuration files && \
    ls -lR ${USER_HOME}

WORKDIR ${USER_HOME}
USER ${USER}

ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]
CMD ["python3", "/usr/bin/ddr53-client.py", "-d"]
