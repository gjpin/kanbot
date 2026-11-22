#!/bin/sh
# Downloads the pinned protoc into codegen/.protoc/ (git-ignored), checking
# its SHA-256. Only regenerating the client needs it; building does not.
set -eu

# renovate: datasource=github-releases depName=protocolbuffers/protobuf
version=36.2
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) asset=osx-aarch_64; sha=9cd98a532c5c5e0c4161314de0225de27e4c8a323917b6ea7b1b714d3ae23466 ;;
  Darwin-x86_64) asset=osx-x86_64; sha=228cc7add4616cc14ca5e80dee83209d44449a7aee95a914ae748fa374efb078 ;;
  Linux-x86_64) asset=linux-x86_64; sha=121f6c7afe1d4d0e3ea6aab9432038599250134cbf4474cb1167d2c7decd4278 ;;
  Linux-aarch64) asset=linux-aarch_64; sha=8b8f18bd2b30346efbc698dd5a73dd7c805f3ef8380f6dfc95c768f3f1852f6a ;;
  *) printf 'no pinned protoc for %s-%s\n' "$(uname -s)" "$(uname -m)" >&2; exit 1 ;;
esac

dir="$(cd "$(dirname "$0")" && pwd)/.protoc"
[ -x "$dir/bin/protoc" ] && [ "$("$dir/bin/protoc" --version)" = "libprotoc $version" ] && exit 0
rm -rf "$dir"
mkdir -p "$dir"
zip="$dir/protoc.zip"
trap 'rm -f "$zip"' EXIT
# HTTPS only, also through redirects; bounded in time.
curl -sSfL --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 10 --max-time 300 -o "$zip" \
  "https://github.com/protocolbuffers/protobuf/releases/download/v$version/protoc-$version-$asset.zip"
if command -v sha256sum >/dev/null; then
  printf '%s  %s\n' "$sha" "$zip" | sha256sum -c -
else
  printf '%s  %s\n' "$sha" "$zip" | shasum -a 256 -c -
fi
unzip -q "$zip" -d "$dir"
"$dir/bin/protoc" --version
