FROM alpine:3.23

#alpine uses apk, not debian based, doesn't interrupt installs 
RUN apk add --no-cache \
    iptables \
    iproute2

CMD ["tail", "-f", "/dev/null"]

