# Person OSINT Web — Enterprise

Fitur: Case ID • Report HTML & PDF • JWT RBAC • Rate limit • Maigret • Holehe • ExifTool • Wayback • PhoneInfoga • HIBP • Hunter • Clearbit

## Jalankan (lokal)
```bash
docker compose build
docker compose up -d
# UI  -> http://localhost:5173
# API -> http://localhost:8000/docs
# PhoneInfoga UI opsional -> http://localhost:8080
```
Login JWT demo: `admin/admin123`, `analyst/analyst123`, `viewer/viewer123` (ubah di compose).

## ENV Penting
- JWT: `JWT_SECRET`, `USERS_JSON`
- Rate limit: `RATELIMIT_PER_MIN` (default 60)
- Third-party: `HIBP_API_KEY`, `HUNTER_API_KEY`, `CLEARBIT_API_KEY`
- PhoneInfoga: `NUMVERIFY_API_KEY`, `GOOGLE_API_KEY`, `GOOGLECSE_CX`
