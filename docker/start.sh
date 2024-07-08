#!/bin/sh

if [ -n "${UMASK}" ]; then
    umask "${UMASK}"
fi

if [ -r /etc/vaultwarden.sh ]; then
    . /etc/vaultwarden.sh
elif [ -r /etc/bitwarden_rs.sh ]; then
    echo "### You are using the old /etc/bitwarden_rs.sh script, please migrate to /etc/vaultwarden.sh ###"
    . /etc/bitwarden_rs.sh
fi

if [ -d /etc/vaultwarden.d ]; then
    for f in /etc/vaultwarden.d/*.sh; do
        if [ -r "${f}" ]; then
            . "${f}"
        fi
    done
elif [ -d /etc/bitwarden_rs.d ]; then
    echo "### You are using the old /etc/bitwarden_rs.d script directory, please migrate to /etc/vaultwarden.d ###"
    for f in /etc/bitwarden_rs.d/*.sh; do
        if [ -r "${f}" ]; then
            . "${f}"
        fi
    done
fi

if [ "$SSO_FRONTEND" = "override" ] ; then
    echo "### Running web-vault frontend with SSO override ###"
    export WEB_VAULT_FOLDER="/web-vault_override"
else
    echo "### Running web-vault frontend with SSO button ###"
    export WEB_VAULT_FOLDER="/web-vault_button"
fi

exec /vaultwarden "${@}"
