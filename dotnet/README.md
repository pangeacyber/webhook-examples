# .NET

This example demonstrates how to receive a webhook notification from Pangea in .NET.

## Prerequisites

- .NET 8.0 SDK or greater.
- `SIGNING_SECRET` environment variable set to the signing secret of the
  webhook.

## Usage

```shell
dotnet run
```

This will launch a server on port 8080. When a webhook is sent to the `/webhook`
route, the signature will be verified and then the payload will be decrypted
and logged to stdout. A tool like Cloudflare Tunnel may be used to expose the
server so that Pangea may reach it.
