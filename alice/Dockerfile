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
      tor \
      xz-utils \
      iproute2 \
      iptables \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*


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
echo 'Waiting for network setup...' && \
sleep 5 && \
echo 'test' && \
ping -c 2 -W 2 172.28.0.2 || echo 'WARNING: Cannot reach bob' && \
echo 'Testing connectivity to NAT...' && \
ping -c 2 -W 2 172.29.0.10 || echo 'WARNING: Cannot reach NAT' && \
echo 'Testing internet connectivity...' && \
ping -c 2 -W 2 8.8.8.8 || echo 'WARNING: Cannot reach internet' && \

echo 'Starting Tor...' && \
service tor start && \
echo 'Waiting for Tor to bootstrap...' && \
sleep 15 && \
echo 'Running crawler...' && \
python3 /workspace/crawler.py && \
echo 'complete' && \
tail -f /dev/null \
"]





