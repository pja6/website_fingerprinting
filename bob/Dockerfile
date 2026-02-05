FROM kalilinux/kali-rolling
#COPY fServer.py ./
#COPY controller.py ./

#useful for docker - doesn't interrupt installs w/ question, assumes default answer
ENV DEBIAN_FRONTEND=noninteractive

#convenient way of running all commands w/o multiple RUN statements
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      python3 \
      python3-pip \
      python3-scapy \
      tcpdump \
      iputils-ping \
      traceroute \
      curl \
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


#keeps container alive indefinitely, since nothing is being run at the moment.
CMD ["tail", "-f", "/dev/null"]
#CMD ["python3", "controller.py"]


