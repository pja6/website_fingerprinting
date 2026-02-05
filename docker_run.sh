# build all images
docker compose build

# start the network
docker compose up -d

# verify routing from alice
docker compose exec alice ip route

# test internet connectivity from alice through bob and NAT
docker compose exec alice ping -c 3 1.1.1.1

# verify routing for bob
docker compose exec bob ip route

# confirm on-path topology
docker compose exec alice traceroute -n 1.1.1.1

# test internet connectivity from bob through NAT
docker compose exec bob ping -c 3 1.1.1.1

# check tcpdump is running on Bob
docker compose exec bob ps aux | grep tcpdump

# when ready to use Tor from Alice:
#docker compose exec alice /opt/tor/tor/tor