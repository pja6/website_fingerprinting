#ALICE dockerfile
FROM kalilinux/kali-rolling
#COPY fServer.py ./
#COPY controller.py ./

#useful for docker - doesn't interrupt installs w/ question, assumes default answer
ENV DEBIAN_FRONTEND=noninteractive

#convenient way of running all commands w/o multiple RUN statements
#alice only needs to curl list of webpages randomly through tor client - can be done w/ script
RUN apt-get update && \ 
    apt-get install -y --no-install-recommends \
      python3\
      python3-scapy\
      tcpdump \
      iputils-ping \
      traceroute\
      curl \
      tar \
      xz-utils \
      iproute2 \
      iptables \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/tor
#download tor expert bundle
RUN curl -L \
    -o tor.tar.gz \
    https://archive.torproject.org/tor-package-archive/torbrowser/15.0.4/tor-expert-bundle-linux-x86_64-15.0.4.tar.gz \
 && tar -xzf tor.tar.gz \
 && rm tor.tar.gz 

# Prev. command from compose, copying for entrypoint
 #   sh -c "
  #    ip route del default &&
  #    ip route add default via 172.28.0.2 &&
  #    tail -f /dev/null
  #  "

#have to use entrypoint
ENTRYPOINT ["sh", "-c", "\
ip route del default && \
ip route add default via 172.28.0.2 && \
python3 /workspace/crawler.py \

"]





