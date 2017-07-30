# UES Auth API

The goal of this service is to provide a simple authentication mechanism for the
Universal Event Store. It provides a simple OAuth2 workflow to obtain credentials
which can be used with the UES Command and Query APIs.

## Running with Docker Compose

```sh
docker-compose up
```

## Interface

### Email-based Authentication

#### GET /authorize

Presents an HTML form requesting an account's login credentials.

Query Params:

- `client-id`
- `callback`

#### POST /authorize

Form Params:

- `email`
- `password`
- `client-id`
- `callback`

Validates that the provided credentials match a valid account. Also
confirms the specified `callback` url matches the record for the
specified `client-id`.
