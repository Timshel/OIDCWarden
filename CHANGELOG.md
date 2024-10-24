# Changelog

# v2024.10.2-1
- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version `v2024.10.2-1`
- :warning: Breaking change :warning:
  - `SSO_PKCE` is now on by default, if you are running Zitadel you'll probably need to set it to `false` since it's incompatible with `CLIENT_SECRET`
  - On first SSO login if the provider does not return the email verification status log in will be blocked.
    Check the [documentation](https://github.com/Timshel/vaultwarden/blob/main/SSO.md#on-sso_allow_unknown_email_verification) for more details.
- Integrate latest change from `Vaultwarden` up to [f60502a1](https://github.com/dani-garcia/vaultwarden/commit/f60502a17e578cbfcd98bfd4763dc054948c1662)

# v2024.8.3-3

- Integrate latest change from `Vaultwarden` [1.32.1](https://github.com/dani-garcia/vaultwarden/discussions/5036#discussioncomment-10838594)

# v2024.8.3-2

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version to `v2024.8.3-4`

# v2024.8.3-1

- Use [oidc_web_vault](https://github.com/Timshel/oidc_web_vault) version to `v2024.8.3-1`
