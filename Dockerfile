# Constat — image de production.
#
# Contient les quatre binaires : constat-server (usage principal de l'image),
# constat (CLI), constat-agent et constat-verify.
#
# Conformément au §17 de l'architecture : compilation depuis les sources,
# aucune dépendance d'exécution au-delà de la libc (rustls, pas d'OpenSSL),
# utilisateur non root.

FROM rust:1.97-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked \
    -p constat-cli -p constat-agent -p constat-server -p constat-verify

FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="Constat" \
      org.opencontainers.image.description="L'état de votre infrastructure dans la durée, avec preuve. Lecture seule, journal Merkle signé, vérifiable sans l'outil." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/yannbanas/constat"

RUN useradd --system --create-home --home-dir /var/lib/constat constat
COPY --from=build /src/target/release/constat \
                  /src/target/release/constat-agent \
                  /src/target/release/constat-server \
                  /src/target/release/constat-verify \
                  /usr/local/bin/
COPY LICENSE NOTICE /usr/share/doc/constat/

USER constat
WORKDIR /var/lib/constat
VOLUME /var/lib/constat

# Le serveur exige ses certificats mTLS en arguments : il refuse de démarrer
# sans eux (pas de mode dégradé). Montez-les et surchargez la commande :
#   docker run -v ./pki:/pki -v constat-data:/var/lib/constat \
#     ghcr.io/yannbanas/constat constat-server run \
#     --listen 0.0.0.0:8443 --cert /pki/server.pem --key /pki/server.key \
#     --client-ca /pki/agents-ca.pem --store /var/lib/constat/constat.redb
ENTRYPOINT []
CMD ["constat-server", "--help"]
