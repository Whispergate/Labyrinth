#!/bin/bash
# Initialize build cache directories for MAAS Jenkins runners
# Run on each Jenkins agent host
CACHE_BASE=/var/cache/maas
dirs=(nimble nim-cache gomod gobuild cargo-registry cargo-git nuget)
for d in "${dirs[@]}"; do
    mkdir -p "$CACHE_BASE/$d"
    chown 989:989 "$CACHE_BASE/$d"
done
