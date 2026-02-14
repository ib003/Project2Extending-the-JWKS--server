# JWKS Server (Project 1)

## Endpoints
- `GET /.well-known/jwks.json` (also available at `GET /jwks`)
  - Returns JWKS public keys
  - Only returns unexpired keys

- `POST /auth`
  - Returns an unexpired RS256 JWT (mock auth; no body required)

- `POST /auth?expired=true`
  - Returns a JWT signed with an expired key
  - JWT includes an expired exp claim

## Run
```bash
go mod tidy
go run .