#!/bin/sh
# Runs the end-to-end sign-in test on Linux desktop (README.md). Needs the
# local stack and the backend running with backend/dev/dev.env, and the
# backend's dev-token example built (backend/target/debug/examples/).
#
# It registers a stand-in default browser for this run only: a desktop
# entry that hands the login URL to `dev-token --sign-in`, which signs
# alice in at Authelia like a person would. It also starts a throwaway
# D-Bus session with an unlocked GNOME keyring (flutter_secure_storage
# needs a Secret Service) and a virtual display.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
frontend=$(dirname "$here")
dev_token=${DEV_TOKEN:-$(dirname "$frontend")/backend/target/debug/examples/dev-token}
[ -x "$dev_token" ] || {
  echo "build it first: (cd backend && cargo build --example dev-token)" >&2
  exit 1
}

home=$(mktemp -d)
trap 'rm -rf "$home"' EXIT
export XDG_DATA_HOME="$home/data" XDG_CONFIG_HOME="$home/config"
mkdir -p "$XDG_DATA_HOME/applications" "$XDG_CONFIG_HOME"

cat >"$home/browser" <<SCRIPT
#!/bin/sh
exec "$dev_token" alice --sign-in "\$1" >>"$home/browser.log" 2>&1
SCRIPT
chmod +x "$home/browser"
cat >"$XDG_DATA_HOME/applications/kanbot-dev-browser.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=kanbot dev browser
Exec=$home/browser %u
MimeType=x-scheme-handler/http;x-scheme-handler/https;
NoDisplay=true
DESKTOP
cat >"$XDG_CONFIG_HOME/mimeapps.list" <<MIME
[Default Applications]
x-scheme-handler/http=kanbot-dev-browser.desktop
x-scheme-handler/https=kanbot-dev-browser.desktop
MIME

cd "$frontend"
status=0
dbus-run-session -- sh -c '
  printf dev | gnome-keyring-daemon --unlock --components=secrets >/dev/null
  xvfb-run -a flutter test integration_test/sign_in_test.dart -d linux \
    --dart-define=API_BASE_URL=http://localhost:3000
' || status=$?
if [ "$status" -ne 0 ] && [ -f "$home/browser.log" ]; then
  echo "--- dev browser log" >&2
  cat "$home/browser.log" >&2
fi
exit "$status"
