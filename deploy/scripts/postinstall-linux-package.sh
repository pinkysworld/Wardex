#!/bin/sh
set -eu

if ! getent group wardex >/dev/null 2>&1; then
  groupadd --system wardex
fi

if ! id -u wardex >/dev/null 2>&1; then
  useradd \
    --system \
    --gid wardex \
    --home-dir /var/lib/wardex \
    --shell /usr/sbin/nologin \
    --comment "Wardex service account" \
    wardex
fi

mkdir -p /etc/wardex /var/lib/wardex /var/log/wardex
chown wardex:wardex /var/lib/wardex /var/log/wardex

if [ ! -f /etc/wardex/wardex.toml ]; then
  /usr/bin/wardex init-config /etc/wardex/wardex.toml >/dev/null 2>&1 || true
fi

if [ -f /etc/wardex/wardex.toml ]; then
  chown root:wardex /etc/wardex/wardex.toml
  chmod 640 /etc/wardex/wardex.toml
fi