#!/usr/bin/env bash
# Assemble les paquets Linux de Constat : .deb (dpkg-deb) et .rpm (rpmbuild)
# à partir de squelettes de contrôle versionnés dans packaging/ — explicite,
# auditable, sans magie (§17). Aucun cargo-deb, aucun outil qui réécrit les
# manifests : les binaires sont compilés par cargo, puis rangés.
#
# Trois paquets (aucun binaire dupliqué, co-installation agent+serveur
# possible sur la machine qui audite le serveur lui-même) :
#   constat-tools   : constat + constat-verify
#   constat-agent   : constat-agent  (+ unités systemd, dépend de constat-tools)
#   constat-server  : constat-server (+ unité systemd,  dépend de constat-tools)
#
# Usage :
#   packaging/build-packages.sh [--target <triple>] [--out <dir>] [--skip-build] [--version <v>]
#
# Prérequis : cargo (sauf --skip-build), dpkg-deb pour les .deb, rpmbuild
# pour les .rpm. Un outil absent est signalé et son format est sauté — le
# script ne fait jamais semblant.
set -euo pipefail

TARGET="x86_64-unknown-linux-gnu"
OUT=""
SKIP_BUILD=0
VERSION=""

while [ $# -gt 0 ]; do
    case "$1" in
        --target)     TARGET="$2"; shift 2 ;;
        --out)        OUT="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --version)    VERSION="$2"; shift 2 ;;
        -h|--help)    sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "option inconnue : $1" >&2; exit 2 ;;
    esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG="$ROOT/packaging"
OUT="${OUT:-$ROOT/dist-packages}"

# Version : celle du workspace ([workspace.package] de Cargo.toml), sauf
# surcharge explicite. Une seule source de vérité.
if [ -z "$VERSION" ]; then
    VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -n 1)"
fi
if [ -z "$VERSION" ]; then
    echo "impossible de lire la version du workspace dans $ROOT/Cargo.toml" >&2
    exit 1
fi

case "$TARGET" in
    x86_64-*)  DEB_ARCH="amd64"; RPM_ARCH="x86_64" ;;
    aarch64-*) DEB_ARCH="arm64"; RPM_ARCH="aarch64" ;;
    *) echo "cible non gérée : $TARGET (attendu x86_64-* ou aarch64-*)" >&2; exit 2 ;;
esac

if [ "$SKIP_BUILD" -eq 0 ]; then
    echo ">> cargo build --release --locked --target $TARGET"
    (cd "$ROOT" && cargo build --release --locked --target "$TARGET" \
        -p constat-cli -p constat-agent -p constat-server -p constat-verify)
fi

BIN="$ROOT/target/$TARGET/release"
for bin in constat constat-agent constat-server constat-verify; do
    if [ ! -f "$BIN/$bin" ]; then
        echo "binaire manquant : $BIN/$bin (compilez d'abord, ou retirez --skip-build)" >&2
        exit 1
    fi
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

# ---------------------------------------------------------------- .deb ----
build_deb() {
    # build_deb <paquet> <binaire...> — assemble un .deb depuis le squelette
    # packaging/deb/<paquet>/ (control.in + scripts de maintenance).
    local name="$1"; shift
    local root="$WORK/deb/$name"
    local skel="$PKG/deb/$name"

    mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/usr/share/doc/$name"
    sed -e "s/@VERSION@/$VERSION/g" -e "s/@ARCH@/$DEB_ARCH/g" \
        "$skel/control.in" > "$root/DEBIAN/control"
    for script in postinst prerm postrm; do
        if [ -f "$skel/$script" ]; then
            install -m 0755 "$skel/$script" "$root/DEBIAN/$script"
        fi
    done
    if [ -f "$skel/conffiles" ]; then
        install -m 0644 "$skel/conffiles" "$root/DEBIAN/conffiles"
    fi

    local bin
    for bin in "$@"; do
        install -m 0755 "$BIN/$bin" "$root/usr/bin/$bin"
    done
    install -m 0644 "$ROOT/LICENSE" "$root/usr/share/doc/$name/copyright"

    case "$name" in
        constat-agent)
            install -D -m 0644 "$PKG/systemd/constat-agent.service" \
                "$root/usr/lib/systemd/system/constat-agent.service"
            install -D -m 0644 "$PKG/systemd/constat-agent.timer" \
                "$root/usr/lib/systemd/system/constat-agent.timer"
            install -D -m 0640 "$PKG/etc/agent.env" "$root/etc/constat/agent.env"
            ;;
        constat-server)
            install -D -m 0644 "$PKG/systemd/constat-server.service" \
                "$root/usr/lib/systemd/system/constat-server.service"
            install -D -m 0640 "$PKG/etc/server.env" "$root/etc/constat/server.env"
            ;;
    esac

    dpkg-deb --build --root-owner-group "$root" \
        "$OUT/${name}_${VERSION}_${DEB_ARCH}.deb"
}

if command -v dpkg-deb >/dev/null 2>&1; then
    build_deb constat-tools constat constat-verify
    build_deb constat-agent constat-agent
    build_deb constat-server constat-server
else
    echo "AVERTISSEMENT : dpkg-deb introuvable — paquets .deb non construits." >&2
fi

# ---------------------------------------------------------------- .rpm ----
if command -v rpmbuild >/dev/null 2>&1; then
    STAGING="$WORK/rpm-staging"
    mkdir -p "$STAGING/bin" "$STAGING/systemd" "$STAGING/etc"
    for bin in constat constat-agent constat-server constat-verify; do
        install -m 0755 "$BIN/$bin" "$STAGING/bin/$bin"
    done
    install -m 0644 "$PKG"/systemd/*.service "$PKG"/systemd/*.timer "$STAGING/systemd/"
    install -m 0644 "$PKG/etc/agent.env" "$PKG/etc/server.env" "$STAGING/etc/"
    install -m 0644 "$ROOT/LICENSE" "$ROOT/NOTICE" "$STAGING/"

    SPEC="$WORK/constat.spec"
    sed -e "s/@VERSION@/$VERSION/g" -e "s/@RPM_ARCH@/$RPM_ARCH/g" \
        "$PKG/rpm/constat.spec.in" > "$SPEC"

    rpmbuild -bb "$SPEC" \
        --define "_topdir $WORK/rpmtop" \
        --define "_constat_staging $STAGING" \
        --target "$RPM_ARCH"
    find "$WORK/rpmtop/RPMS" -name '*.rpm' -exec cp {} "$OUT/" \;
else
    echo "AVERTISSEMENT : rpmbuild introuvable — paquets .rpm non construits." >&2
fi

# ---------------------------------------------------- empreintes SHA-256 ----
# Une empreinte par paquet, comme pour les archives de release (§17).
(
    cd "$OUT"
    for f in *.deb *.rpm; do
        [ -f "$f" ] || continue
        sha256sum "$f" > "$f.sha256"
    done
)

echo ">> paquets dans $OUT :"
ls -l "$OUT"
