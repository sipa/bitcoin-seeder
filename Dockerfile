FROM debian:12 AS builder
COPY . /srv/
RUN apt update 
RUN apt -y install build-essential libboost-all-dev libssl-dev 
WORKDIR /srv
RUN make

FROM debian:12
RUN apt update && \
    apt install -y libssl3 --no-install-recommends && \
    apt clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
WORKDIR /home/dnsseed
COPY --from=builder /srv/dnsseed /home/dnsseed/
COPY entrypoint.sh /

# Set the entrypoint to your script
ENTRYPOINT ["/entrypoint.sh"]

# Default CMD if no arguments are provided (this can be overwritten at runtime)
CMD ["/home/dnsseed/dnsseed"]
