#!/usr/bin/env bash
# Builds release archives into dist/. Needs cargo-zigbuild and zig on PATH.
# Each archive holds both the client (lagrelay) and the relay (lagrelayd).
set -euo pipefail
cd "$(dirname "$0")/.."
WD_VER=2.2.2
WD_SHA=63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15
cargo zigbuild --release --target x86_64-pc-windows-gnu -p lagrelay -p lagrelayd
cargo zigbuild --release --target x86_64-unknown-linux-musl -p lagrelay -p lagrelayd
cargo zigbuild --release --target aarch64-unknown-linux-musl -p lagrelay -p lagrelayd
mkdir -p dist/.cache
ZIP=dist/.cache/WinDivert-$WD_VER-A.zip
[ -f "$ZIP" ] || curl -fsSL -o "$ZIP" "https://github.com/basil00/WinDivert/releases/download/v$WD_VER/WinDivert-$WD_VER-A.zip"
echo "$WD_SHA  $ZIP" | sha256sum -c -
rm -rf dist/lagrelay-windows-x64 dist/lagrelay-linux-x64 dist/lagrelay-linux-arm64
mkdir -p dist/lagrelay-windows-x64 dist/lagrelay-linux-x64 dist/lagrelay-linux-arm64
python3 -m zipfile -e "$ZIP" dist/.cache/
W=dist/.cache/WinDivert-$WD_VER-A
cp target/x86_64-pc-windows-gnu/release/lagrelay.exe target/x86_64-pc-windows-gnu/release/lagrelayd.exe "$W/x64/WinDivert.dll" "$W/x64/WinDivert64.sys" dist/lagrelay-windows-x64/
cp "$W/LICENSE" dist/lagrelay-windows-x64/WinDivert-LICENSE.txt
cp README.md dist/lagrelay-windows-x64/
cp target/x86_64-unknown-linux-musl/release/lagrelay target/x86_64-unknown-linux-musl/release/lagrelayd install.sh README.md dist/lagrelay-linux-x64/
cp target/aarch64-unknown-linux-musl/release/lagrelay target/aarch64-unknown-linux-musl/release/lagrelayd install.sh README.md dist/lagrelay-linux-arm64/
(cd dist && tar czf lagrelay-linux-arm64.tar.gz lagrelay-linux-arm64 && rm -f lagrelay-windows-x64.zip && python3 -m zipfile -c lagrelay-windows-x64.zip lagrelay-windows-x64/ && tar czf lagrelay-linux-x64.tar.gz lagrelay-linux-x64)
cp install.sh dist/install.sh
(cd dist && sha256sum lagrelay-windows-x64.zip lagrelay-linux-x64.tar.gz lagrelay-linux-arm64.tar.gz > SHA256SUMS.txt)
ls -la dist/*.zip dist/*.tar.gz
