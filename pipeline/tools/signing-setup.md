# Limelighter Signing Setup

Limelighter generates fake code-signing certificates and signs PE files to evade
static analysis that checks for valid signatures.

GitHub: https://github.com/Tylous/Limelighter

## Adding Limelighter to the Go Builder Image

### Option 1: Install in existing maas-builder-go image

Add to `Dockerfile.maas-builder-go.j2`:

```dockerfile
# Install Limelighter for PE signing
RUN go install github.com/Tylous/Limelighter@latest \
    && cp /root/go/bin/Limelighter /usr/local/bin/
```

### Option 2: Manual build

```bash
git clone https://github.com/Tylous/Limelighter.git
cd Limelighter
go build -o /usr/local/bin/Limelighter .
```

## Dependencies

Limelighter requires:
- Go 1.17+ (already in maas-builder-go)
- OpenSSL libraries (`libssl-dev` / `openssl`)

If OpenSSL is not in the builder image, add:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev openssl \
    && rm -rf /var/lib/apt/lists/*
```

## Usage

Clone a real certificate from a domain:
```
Limelighter -I input.exe -O output.exe -Domain www.microsoft.com -Real
```

Generate a self-signed certificate with a custom domain:
```
Limelighter -I input.exe -O output.exe -Domain internal-tools.contoso.com -Password changeme
```

## Signing Profiles

See `signing-profiles.yml` for predefined profiles. The Jenkins pipeline reads
the selected profile and passes the appropriate flags to Limelighter.
