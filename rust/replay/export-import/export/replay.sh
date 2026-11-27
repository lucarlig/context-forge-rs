#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu
umask 077

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    printf '%s\n' 'Usage: sh replay.sh /absolute/path/context-forge-rs [sqlite|postgres]' >&2
    exit 2
fi

binary=$1
backend=${2:-sqlite}
suite=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

export JWT_SECRET_KEY
JWT_SECRET_KEY=$(openssl rand -hex 32)
export AUTH_ENCRYPTION_SECRET=context-forge-auth-api-encryption-fixture-key
export HOST=127.0.0.1

case "$backend" in
    sqlite)
        export DATABASE_URL="sqlite:///$fixture/export.sqlite3"
        cp -R "$suite/rust" "$fixture/"
        "$binary" migrate
        sqlite3 "$fixture/export.sqlite3" < "$suite/fixture.sql"
        ;;
    postgres)
        : "${DATABASE_URL:?Set DATABASE_URL to an empty PostgreSQL fixture database}"
        cp -R "$suite/postgres/rust" "$fixture/"
        "$binary" migrate
        psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$suite/fixture.sql"
        ;;
    *)
        printf '%s\n' 'Expected sqlite or postgres' >&2
        exit 2
        ;;
esac

base64url() {
    openssl base64 -A | tr '+/' '-_' | tr -d '='
}

jwt() {
    subject=$1
    teams=$2
    administrator=$3
    scopes=$4
    now=$(date +%s)
    jwt_header=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | base64url)
    payload=$(printf '{"sub":"%s","iss":"mcpgateway","aud":"mcpgateway-api","iat":%s,"exp":%s,"jti":"%s","is_admin":%s,"teams":%s,"token_use":"api","scopes":%s}' \
        "$subject" "$now" "$((now + 1800))" "$(openssl rand -hex 16)" "$administrator" "$teams" "$scopes" | base64url)
    unsigned="$jwt_header.$payload"
    signature=$(printf '%s' "$unsigned" | openssl dgst -sha256 -hmac "$JWT_SECRET_KEY" -binary | base64url)
    printf '%s.%s\n' "$unsigned" "$signature"
}

admin=$(jwt admin@example.com null true '{}')
team=$(jwt exporter@example.com '["export-team"]' false '{}')
public=$(jwt exporter@example.com '[]' false '{}')
viewer=$(jwt viewer@example.com '[]' false '{}')
restricted=$(jwt exporter@example.com '["export-team"]' false '{"permissions":["tools.read"]}')
for case_file in "$fixture"/rust/app-cases/http/*.toml; do
    sed -e "s/@export-administrator@/$admin/g" -e "s/@export-team@/$team/g" \
        -e "s/@export-public@/$public/g" -e "s/@export-viewer@/$viewer/g" \
        -e "s/@export-restricted@/$restricted/g" "$case_file" > "$case_file.tmp"
    mv "$case_file.tmp" "$case_file"
done
rust-anything app replay "$fixture" --build "$binary" --redact
