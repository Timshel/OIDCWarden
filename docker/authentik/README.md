# OpenID Connect test setup

This `docker-compose` template allow to run locally a `OIDCWarden` and [`Authentik`](https://goauthentik.io/) instance to test OIDC.

## Usage

This rely on `docker` and the `compose` [plugin](https://docs.docker.com/compose/install/).

First create a copy of `.env.template` as `.env` (This is done to prevent committing your custom settings, Ex `SMTP_`).

Then start the stack (the `profile` is required to run `OIDCWarden`).

```bash
> DOCKER_BUILDKIT=1 docker compose --profile warden up Warden
```

Then you can access :

 - `OIDCWarden` on http://127.0.0.1:8000 with the default user `test@yopmail.com/test`.
 - `Authentik` on http://127.0.0.1:9000/ with the default user `akadmin/admin`

## Switching front-end

You can switch between both [version](https://github.com/Timshel/oidc_web_vault) of the front-end using the env variable `SSO_FRONTEND` with `button` or `override` (default is `button`).

## Running only Authentik

Since the server is defined with a `profile` you can just use the default `docker-compose` command :

```bash
> DOCKER_BUILDKIT=1 docker compose up
```

When running with a local project, you will need a prebuilt front-end from [timshel/oidc_web_vault](https://github.com/Timshel/oidc_web_vault/releases).

## To force rebuilding the VaultWarden image

Use `DOCKER_BUILDKIT=1 docker-compose --profile VaultWarden up --build VaultWarden`.

If after building the `Authentik` configuration is not run, just interrupt and run without `--build`

## Cleanup

Use `docker-compose --profile VaultWarden down`.

## Issues

At the moment the access token lifetime is set to `5min` which will collide with the expiration detection of `VaultWarden` which is set to `5min` too.
This might result in spamming of the refresh token endpoint and race condition might trigger a logout.
