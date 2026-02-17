docker compose -f caddy/docker-compose.yaml up -d
docker compose -f static/docker-compose.yaml up -d
docker compose -f postgres/docker-compose.yaml up -d
docker compose -f authentik/docker-compose.yaml up -d
