# Python

This example demonstrates how to receive a webhook notification from Pangea in
Python.

## Prerequisites

- Python v3.12 or greater.
- uv v0.6.16 or greater.
- `SIGNING_SECRET` environment variable set to the signing secret of the
  webhook.

## Usage

```shell
uv run server.py
```

This will launch a server on port 8080. When a webhook is sent to the `/webhook`
route, the signature will be verified and then the payload will be decrypted
and logged to stdout.
