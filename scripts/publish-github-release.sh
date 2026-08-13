#!/usr/bin/env bash
# Publish a GitHub Release when FELIX_CONNECTOR_VERSION has no matching tag.
# Merging to main does not create a Release; this is the missing CI step.
# Safe to re-run: skips if v{version} already exists.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ZIP="${ROOT}/dist/felix-connector.zip"
if [[ ! -f "$ZIP" ]]; then
	echo "Missing ${ZIP}" >&2
	exit 1
fi

VERSION="$(grep -oP "define\( 'FELIX_CONNECTOR_VERSION', '\K[^']+" felix-connector.php || true)"
STABLE="$(grep -oP '^Stable tag: \K.+' readme.txt || true)"

if [[ -z "$VERSION" ]]; then
	echo "Could not read FELIX_CONNECTOR_VERSION" >&2
	exit 1
fi
if [[ "$VERSION" != "$STABLE" ]]; then
	echo "Version mismatch: plugin=${VERSION} readme Stable tag=${STABLE}" >&2
	exit 1
fi

TAG="v${VERSION}"

if gh release view "$TAG" >/dev/null 2>&1; then
	echo "Release ${TAG} already exists — skipping"
	exit 0
fi

NOTES="$(awk -v ver="$VERSION" '
	$0 == "= " ver " =" { p=1; next }
	p && $0 ~ /^= / { exit }
	p { print }
' readme.txt | sed -e 's/[[:space:]]*$//' )"

if [[ -z "$NOTES" ]]; then
	NOTES="Felix Connector ${TAG}"
fi

gh release create "$TAG" \
	--title "Felix Connector ${TAG}" \
	--notes "$NOTES" \
	"$ZIP"

echo "Published ${TAG} with $(basename "$ZIP")"
