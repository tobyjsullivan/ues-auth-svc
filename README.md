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

**Response**

200 OK

```json
{
  "data": {
    "token": "6a0477e28c8d2e2d9bb05...",
    "expires": 86399
  }
}
```

For a successful response, the `data` property will include a `token`
property containing
an active authorization token for the user. The `expires` field contains
the number of seconds remaining until the token expires.

In the event of an error, the response will contain an `error` value instead
of `data`.

#### POST /verify

Verify a given auth-token and return the associated owner. The token
must have been issued for the specified `client-id`.

Form Params:

- `token`
- `client-id`
- `secret`

**Response**

200 OK

```json
{
  "data": {
    "accountId": "0723acb0-ffeb-4f34-8fc3-c38b411764b4",
    "expires": 81264
  }
}
```

If the given `token` is valid, a `200 OK` response will include the
`accountId` associated with the token. Additionally, `expires` will
indicate the number of seconds until the token expires.
