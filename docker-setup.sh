sudo docker network create caddy-proxy
sudo docker network create database

PG_PASS="$(openssl rand -base64 36 | tr -d '\n')"
# Generate environment variables
echo "PG_PASS=$PG_PASS" >> .env
echo "AUTHENTIK_SECRET_KEY=$(openssl rand -base64 60 | tr -d '\n')" >> .env