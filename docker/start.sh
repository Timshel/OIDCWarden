#!/bin/sh

if [ -n "${UMASK}" ]; then
    umask "${UMASK}"
fi

if [ -r /etc/oidcwarden.sh ]; then
    . /etc/oidcwarden.sh
fi

if [ -d /etc/oidcwarden.d ]; then
    for f in /etc/oidcwarden.d/*.sh; do
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

exec /oidcwarden "${@}"
