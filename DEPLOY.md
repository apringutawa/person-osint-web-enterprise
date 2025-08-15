# DEPLOY — VPS & Lokal (Copas)
## Lokal
```bash
cd person-osint-web-enterprise
docker compose build
docker compose up -d
```
## VPS Ubuntu
```bash
sudo bash -c "$(cat scripts/install-on-ubuntu.sh)"
cd /opt/person-osint-web-enterprise
docker compose pull
docker compose build
docker compose up -d
ufw allow 5173/tcp; ufw allow 8000/tcp; ufw allow 8080/tcp
```
## Reverse Proxy (Nginx)
```
server { listen 80; server_name osint.example.com;
  location / { proxy_pass http://127.0.0.1:5173; proxy_set_header Host $host; } }
server { listen 80; server_name api.osint.example.com;
  location / { proxy_pass http://127.0.0.1:8000; proxy_set_header Host $host; } }
```
