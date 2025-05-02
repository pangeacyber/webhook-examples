# TypeScript/JavaScript

This example demonstrates how to receive a webhook notification from Pangea in
TypeScript/JavaScript.

## Prerequisites

- Deno v2.2.8 or greater.
- `SIGNING_SECRET` environment variable set to the signing secret of the
  webhook.

## Usage

```shell
deno run --allow-net server.ts
```

This will launch a server on port 8080. When a webhook is sent to the server
(on any path/route), the signature will be verified and then the payload will be
decrypted and logged to stdout. A tool like Cloudflare Tunnel may be used to
expose the server so that Pangea may reach it.
