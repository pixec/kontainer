#!/usr/bin/env sh
# Runs the OCI distribution-spec conformance suite against a registry built from this tree.
#
#   scripts/conformance.sh                 # builds, starts a registry on 127.0.0.1:5055, runs the suite
#   OCI_REGISTRY=registry.example.com OCI_TLS=enabled OCI_USERNAME=u OCI_PASSWORD=p \
#     scripts/conformance.sh --no-server   # against a running registry
#
# Needs Go 1.24+, and for the built-in server a PostgreSQL it can create a database in
# (KONTAINER_TEST_DATABASE_URL, default postgres://kontainer:kontainer@127.0.0.1:55432/kontainer,
# see README "Development"). The suite and results live in .conformance/ (not under target/,
# which CI caches and prunes): report.html, junit.xml, results.yaml under .conformance/results.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SPEC_REF=${OCI_SPEC_REF:-main}
WORK=${OCI_WORK_DIR:-$ROOT/.conformance}
RESULTS=${OCI_RESULTS_DIR:-$WORK/results}
mkdir -p "$WORK" "$RESULTS"

# 1. The suite, built from opencontainers/distribution-spec.
if [ ! -x "$WORK/conformance" ]; then
  # A pruned or partial checkout (a restored cache, an interrupted clone) is replaced.
  if [ ! -f "$WORK/distribution-spec/conformance/go.mod" ]; then
    rm -rf "$WORK/distribution-spec"
    git clone -q --depth 1 --branch "$SPEC_REF" https://github.com/opencontainers/distribution-spec "$WORK/distribution-spec"
  fi
  (cd "$WORK/distribution-spec/conformance" && go build -o "$WORK/conformance" .)
fi

# 2. A registry to test, unless told to use a running one.
if [ "${1:-}" != "--no-server" ]; then
  DB=${KONTAINER_TEST_DATABASE_URL:-postgres://kontainer:kontainer@127.0.0.1:55432/kontainer}
  NAME=kontainer_conformance_$$
  psql_do() { psql "$DB" -qc "$1"; }
  if command -v psql >/dev/null; then
    psql_do "DROP DATABASE IF EXISTS $NAME;" && psql_do "CREATE DATABASE $NAME;"
  else
    docker exec kontainer-pg psql -U kontainer -d kontainer -qc "CREATE DATABASE $NAME;"
  fi
  (cd "$ROOT" && cargo build -q -p kontainer)
  DATA="$WORK/data-$$"; mkdir -p "$DATA"
  cat > "$WORK/config-$$.toml" <<EOF
[server]
bind = "127.0.0.1:5055"
public_url = "http://127.0.0.1:5055"
log = "warn"
[storage]
driver = "filesystem"
upload_dir = "$DATA/_uploads"
[storage.filesystem]
root = "$DATA"
[auth]
mode = "token"
database_url = "${DB%/*}/$NAME"
bootstrap_admin = { username = "conformance", password = "conformance-pass-1" }
[scanner]
kind = "none"
[features]
delete = true
EOF
  KONTAINER_CONFIG="$WORK/config-$$.toml" "$ROOT/target/debug/kontainer" serve >"$WORK/registry-$$.log" 2>&1 &
  SERVER=$!
  trap 'kill $SERVER 2>/dev/null; rm -rf "$DATA" "$WORK/config-$$.toml"' EXIT
  i=0; until curl -fsS http://127.0.0.1:5055/readyz >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 60 ] || { echo "registry did not start; see $WORK/registry-$$.log" >&2; exit 1; }; sleep 1; done
  export OCI_REGISTRY=127.0.0.1:5055 OCI_TLS=disabled OCI_USERNAME=conformance OCI_PASSWORD=conformance-pass-1
fi

# 3. Run it. The suite exits 0 even on failures; its summary says FAIL.
export OCI_VERSION=${OCI_VERSION:-1.1} OCI_RESULTS_DIR="$RESULTS" OCI_LOG=${OCI_LOG:-warn}
export OCI_REPO1=${OCI_REPO1:-conformance/repo1} OCI_REPO2=${OCI_REPO2:-conformance/repo2}
# Off by default in the suite; Kontainer supports cancelling an upload (DELETE on the session).
export OCI_API_BLOBS_UPLOAD_CANCEL=${OCI_API_BLOBS_UPLOAD_CANCEL:-true}
# Also off by default for spec 1.1: pushing a manifest by digest with `?tag=` parameters (end-7b).
export OCI_API_MANIFESTS_TAG_PARAM=${OCI_API_MANIFESTS_TAG_PARAM:-true}
"$WORK/conformance" | tee "$RESULTS/summary.txt"
if grep -q 'detected a failure' "$RESULTS/summary.txt"; then
  echo "conformance: FAIL (see $RESULTS/report.html)" >&2
  exit 1
fi
echo "conformance: PASS ($RESULTS/report.html)"
