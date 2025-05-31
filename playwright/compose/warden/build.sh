#!/bin/bash

echo $REPO_URL
echo $COMMIT_HASH

if [[ ! -z "${REPO_URL}" ]] && [[ ! -z "${COMMIT_HASH}" ]] ; then
    rm -rf /web-vault_button /web-vault_override

    git clone ${REPO_URL} /oidc_web_vault
    cd /oidc_web_vault
    git reset --hard "${COMMIT_HASH}"

    ./build_webvault.sh

    cd /
    tar -xf /oidc_web_vault/oidc_button_web_vault.tar.gz; mv web-vault /web-vault_button
    tar -xf /oidc_web_vault/oidc_override_web_vault.tar.gz; mv web-vault /web-vault_override
fi
