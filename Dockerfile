FROM golang:1.13
MAINTAINER austinkim <austin.njkim@gmail.com>

WORKDIR /go/src/honeypot/

RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*

COPY build.sh build.sh
RUN chmod +x build.sh

CMD ["/bin/bash", "build.sh"]
