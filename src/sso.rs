use chrono::Utc;
use derive_more::{AsRef, Deref, Display, From};
use regex::Regex;
use serde::de::DeserializeOwned;
use serde_with::{serde_as, DefaultOnError};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use url::Url;

use mini_moka::sync::Cache;
use once_cell::sync::Lazy;
use openidconnect::core::{
    CoreClient, CoreIdTokenVerifier, CoreProviderMetadata, CoreResponseType, CoreUserInfoClaims,
};
use openidconnect::reqwest;
use openidconnect::{
    AccessToken, AuthDisplay, AuthPrompt, AuthenticationFlow, AuthorizationCode, AuthorizationRequest, ClientId,
    ClientSecret, CsrfToken, EndpointNotSet, EndpointSet, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RefreshToken, ResponseType, Scope,
};

use crate::{
    api::core::organizations::CollectionData,
    api::ApiResult,
    auth,
    auth::{AuthMethod, AuthTokens, ClientIp, TokenWrapper, BW_EXPIRATION, DEFAULT_REFRESH_VALIDITY},
    business::organization_logic,
    db::{
        models::{
            Device, EventType, GroupId, GroupUser, Membership, MembershipType, Organization, OrganizationId, SsoNonce,
            User, UserId,
        },
        DbConn,
    },
    CONFIG,
};

pub static FAKE_IDENTIFIER: &str = "OIDCWarden";
pub const ACTING_AUTO_ENROLL_USER: &str = "oidcwarden-auto-00000-000000000000";

static AC_CACHE: Lazy<Cache<OIDCState, AuthenticatedUser>> =
    Lazy::new(|| Cache::builder().max_capacity(1000).time_to_live(Duration::from_secs(10 * 60)).build());

static CLIENT_CACHE_KEY: Lazy<String> = Lazy::new(|| "sso-client".to_string());
static CLIENT_CACHE: Lazy<Cache<String, Client>> = Lazy::new(|| {
    Cache::builder().max_capacity(1).time_to_live(Duration::from_secs(CONFIG.sso_client_cache_expiration())).build()
});

static SSO_JWT_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|sso", CONFIG.domain_origin()));

pub static NONCE_EXPIRATION: Lazy<chrono::Duration> = Lazy::new(|| chrono::TimeDelta::try_minutes(10).unwrap());

trait AuthorizationRequestExt<'a> {
    fn add_extra_params<N: Into<Cow<'a, str>>, V: Into<Cow<'a, str>>>(self, params: Vec<(N, V)>) -> Self;
}

impl<'a, AD: AuthDisplay, P: AuthPrompt, RT: ResponseType> AuthorizationRequestExt<'a>
    for AuthorizationRequest<'a, AD, P, RT>
{
    fn add_extra_params<N: Into<Cow<'a, str>>, V: Into<Cow<'a, str>>>(mut self, params: Vec<(N, V)>) -> Self {
        for (key, value) in params {
            self = self.add_extra_param(key, value);
        }
        self
    }
}

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
)]
#[deref(forward)]
#[from(forward)]
pub struct OIDCCode(String);

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
)]
#[deref(forward)]
#[from(forward)]
pub struct OIDCState(String);

#[derive(Debug, Serialize, Deserialize)]
struct SsoTokenJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,
}

pub fn encode_ssotoken_claims() -> String {
    let time_now = Utc::now();
    let claims = SsoTokenJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + chrono::TimeDelta::try_minutes(2).unwrap()).timestamp(),
        iss: SSO_JWT_ISSUER.to_string(),
        sub: "vaultwarden".to_string(),
    };

    auth::encode_jwt(&claims)
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OIDCCodeWrapper {
    Ok {
        state: OIDCState,
        code: OIDCCode,
    },
    Error {
        state: OIDCState,
        error: String,
        error_description: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct OIDCCodeClaims {
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,

    pub code: OIDCCodeWrapper,
}

pub fn encode_code_claims(code: OIDCCodeWrapper) -> String {
    let time_now = Utc::now();
    let claims = OIDCCodeClaims {
        exp: (time_now + chrono::TimeDelta::try_minutes(5).unwrap()).timestamp(),
        iss: SSO_JWT_ISSUER.to_string(),
        code,
    };

    auth::encode_jwt(&claims)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BasicTokenClaims {
    iat: Option<i64>,
    nbf: Option<i64>,
    exp: i64,
}

impl BasicTokenClaims {
    fn nbf(&self) -> i64 {
        self.nbf.or(self.iat).unwrap_or_else(|| Utc::now().timestamp())
    }
}

// IdToken validation is handled by IdToken.claims
// This is only used to retrive additionnal claims which are configurable
// Or to try to parse access_token and refresh_tken as JWT to find exp
fn insecure_decode<T: DeserializeOwned>(token_name: &str, token: &str) -> ApiResult<T> {
    let mut validation = jsonwebtoken::Validation::default();
    validation.set_issuer(&[CONFIG.sso_authority()]);
    validation.insecure_disable_signature_validation();
    validation.validate_aud = false;

    match jsonwebtoken::decode::<T>(token, &jsonwebtoken::DecodingKey::from_secret(&[]), &validation) {
        Ok(btc) => Ok(btc.claims),
        Err(err) => err_silent!(format!("Failed to decode {token_name}: {err}")),
    }
}

#[derive(Clone)]
struct Client {
    http_client: reqwest::Client,
    core_client: CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet, EndpointSet>,
}

impl Client {
    // Call the OpenId discovery endpoint to retrieve configuration
    async fn _get_client() -> ApiResult<Self> {
        let client_id = ClientId::new(CONFIG.sso_client_id());
        let client_secret = ClientSecret::new(CONFIG.sso_client_secret());

        let issuer_url = CONFIG.sso_issuer_url()?;

        let http_client = match reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none()).build() {
            Err(err) => err!(format!("Failed to build http client: {err}")),
            Ok(client) => client,
        };

        let provider_metadata = match CoreProviderMetadata::discover_async(issuer_url, &http_client).await {
            Err(err) => err!(format!("Failed to discover OpenID provider: {err}")),
            Ok(metadata) => metadata,
        };

        let base_client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret));

        let token_uri = match base_client.token_uri() {
            Some(uri) => uri.clone(),
            None => err!("Failed to discover token_url, cannot proceed"),
        };

        let user_info_url = match base_client.user_info_url() {
            Some(url) => url.clone(),
            None => err!("Failed to discover user_info url, cannot proceed"),
        };

        let core_client = base_client
            .set_redirect_uri(CONFIG.sso_redirect_url()?)
            .set_token_uri(token_uri)
            .set_user_info_url(user_info_url);

        Ok(Client {
            http_client,
            core_client,
        })
    }

    // Simple cache to prevent recalling the discovery endpoint each time
    async fn cached() -> ApiResult<Self> {
        if CONFIG.sso_client_cache_expiration() > 0 {
            match CLIENT_CACHE.get(&*CLIENT_CACHE_KEY) {
                Some(client) => Ok(client),
                None => Self::_get_client().await.inspect(|client| {
                    debug!("Inserting new client in cache");
                    CLIENT_CACHE.insert(CLIENT_CACHE_KEY.clone(), client.clone());
                }),
            }
        } else {
            Self::_get_client().await
        }
    }

    async fn user_info(&self, access_token: AccessToken) -> ApiResult<CoreUserInfoClaims> {
        match self.core_client.user_info(access_token, None).request_async(&self.http_client).await {
            Err(err) => err!(format!("Request to user_info endpoint failed: {err}")),
            Ok(user_info) => Ok(user_info),
        }
    }

    fn vw_id_token_verifier(&self) -> CoreIdTokenVerifier<'_> {
        let mut verifier = self.core_client.id_token_verifier();
        if let Some(regex_str) = CONFIG.sso_audience_trusted() {
            match Regex::new(&regex_str) {
                Ok(regex) => {
                    verifier = verifier.set_other_audience_verifier_fn(move |aud| regex.is_match(aud));
                }
                Err(err) => {
                    error!("Failed to parse SSO_AUDIENCE_TRUSTED={regex_str} regex: {err}");
                }
            }
        }
        verifier
    }
}

pub fn deocde_state(base64_state: String) -> ApiResult<OIDCState> {
    let state = match data_encoding::BASE64.decode(base64_state.as_bytes()) {
        Ok(vec) => match String::from_utf8(vec) {
            Ok(valid) => OIDCState(valid),
            Err(_) => err!(format!("Invalid utf8 chars in {base64_state} after base64 decoding")),
        },
        Err(_) => err!(format!("Failed to decode {base64_state} using base64")),
    };

    Ok(state)
}

// The `nonce` allow to protect against replay attacks
// The `state` is encoded using base64 to ensure no issue with providers (It contains the Organization identifier).
// redirect_uri from: https://github.com/bitwarden/server/blob/main/src/Identity/IdentityServer/ApiClient.cs
pub async fn authorize_url(
    state: OIDCState,
    client_id: &str,
    raw_redirect_uri: &str,
    mut conn: DbConn,
) -> ApiResult<Url> {
    let scopes = CONFIG.sso_scopes_vec().into_iter().map(Scope::new);
    let base64_state = data_encoding::BASE64.encode(state.to_string().as_bytes());

    let redirect_uri = match client_id {
        "web" | "browser" => format!("{}/sso-connector.html", CONFIG.domain()),
        "desktop" | "mobile" => "bitwarden://sso-callback".to_string(),
        "cli" => {
            let port_regex = Regex::new(r"^http://localhost:([0-9]{4})$").unwrap();
            match port_regex.captures(raw_redirect_uri).and_then(|captures| captures.get(1).map(|c| c.as_str())) {
                Some(port) => format!("http://localhost:{}", port),
                None => err!("Failed to extract port number"),
            }
        }
        _ => err!(format!("Unsupported client {client_id}")),
    };

    let client = Client::cached().await?;
    let mut auth_req = client
        .core_client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            || CsrfToken::new(base64_state),
            Nonce::new_random,
        )
        .add_scopes(scopes)
        .add_extra_params(CONFIG.sso_authorize_extra_params_vec()?);

    let verifier = if CONFIG.sso_pkce() {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        auth_req = auth_req.set_pkce_challenge(pkce_challenge);
        Some(pkce_verifier.into_secret())
    } else {
        None
    };

    let (auth_url, _, nonce) = auth_req.url();

    let sso_nonce = SsoNonce::new(state, nonce.secret().clone(), verifier, redirect_uri);
    sso_nonce.save(&mut conn).await?;

    Ok(auth_url)
}

#[derive(Debug)]
struct AdditionnalClaims {
    role: Option<UserRole>,
    org_role: Option<UserOrgRole>,
    groups: Vec<String>,
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::enum_variant_names)]
enum UserOrgRole {
    OrgNoSync,
    OrgOwner,
    OrgAdmin,
    OrgManager,
    OrgUser,
}

impl UserOrgRole {
    fn membership_type(&self) -> MembershipType {
        match *self {
            UserOrgRole::OrgOwner => MembershipType::Owner,
            UserOrgRole::OrgAdmin => MembershipType::Admin,
            UserOrgRole::OrgManager => MembershipType::Manager,
            _ => MembershipType::User,
        }
    }
}

#[serde_as]
#[derive(Deserialize)]
struct UserRoles<T: DeserializeOwned>(#[serde_as(as = "Vec<DefaultOnError>")] Vec<Option<T>>);

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
)]
#[deref(forward)]
#[from(forward)]
pub struct OIDCIdentifier(String);

impl OIDCIdentifier {
    fn new(issuer: &str, subject: &str) -> Self {
        OIDCIdentifier(format!("{}/{}", issuer, subject))
    }
}

#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub refresh_token: Option<String>,
    pub access_token: String,
    pub expires_in: Option<Duration>,
    pub identifier: OIDCIdentifier,
    pub email: String,
    pub email_verified: Option<bool>,
    pub user_name: Option<String>,
    pub role: Option<UserRole>,
    org_role: Option<UserOrgRole>,
    groups: Vec<String>,
}

impl AuthenticatedUser {
    pub fn is_admin(&self) -> bool {
        self.role.as_ref().is_some_and(|x| x == &UserRole::Admin)
    }
}

#[derive(Clone, Debug)]
pub struct UserInformation {
    pub state: OIDCState,
    pub identifier: OIDCIdentifier,
    pub email: String,
    pub email_verified: Option<bool>,
    pub user_name: Option<String>,
}

// Return the top most defined Role (https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html#derivable)
fn deserialize_top_role<T: DeserializeOwned + Ord>(
    deserialize: bool,
    email: &str,
    json_roles: &serde_json::Value,
) -> Option<T> {
    use crate::serde::Deserialize;

    if deserialize {
        match UserRoles::<T>::deserialize(json_roles) {
            Ok(UserRoles(mut roles)) => {
                roles.sort();
                roles.into_iter().find(|r| r.is_some()).flatten()
            }
            Err(err) => {
                debug!("Failed to parse user ({email}) roles: {err}");
                None
            }
        }
    } else {
        None
    }
}

// Errors are logged but will return None
fn roles_claim(email: &str, token: &serde_json::Value) -> (Option<UserRole>, Option<UserOrgRole>) {
    if let Some(json_roles) = token.pointer(&CONFIG.sso_roles_token_path()) {
        (
            deserialize_top_role(CONFIG.sso_roles_enabled(), email, json_roles),
            deserialize_top_role(
                CONFIG.sso_organizations_invite() || CONFIG.sso_organizations_enabled(),
                email,
                json_roles,
            ),
        )
    } else {
        debug!("No roles in {email} id_token at {}", &CONFIG.sso_roles_token_path());
        (None, None)
    }
}

// Errors are logged but will return an empty Vec
fn groups_claim(email: &str, token: &serde_json::Value) -> Vec<String> {
    if let Some(json_groups) = token.pointer(&CONFIG.sso_organizations_token_path()) {
        match serde_json::from_value::<Vec<String>>(json_groups.clone()) {
            Ok(groups) => groups,
            Err(err) => {
                error!("Failed to parse user ({email}) groups: {err}");
                Vec::new()
            }
        }
    } else {
        debug!("No groups in {email} id_token at {}", &CONFIG.sso_organizations_token_path());
        Vec::new()
    }
}

// Trying to conditionnally read additionnal configurable claims using openidconnect appear nightmarish
// So we just decode the token again as a JsValue
fn additional_claims(email: &str, token: &str) -> ApiResult<AdditionnalClaims> {
    let mut roles = (None, None);
    let mut groups = Vec::new();

    if CONFIG.sso_roles_enabled() || CONFIG.sso_organizations_invite() || CONFIG.sso_organizations_enabled() {
        match insecure_decode::<serde_json::Value>("id_token", token) {
            Err(err) => err!(format!("Could not decode access token: {:?}", err)),
            Ok(claims) => {
                roles = roles_claim(email, &claims);

                if CONFIG.sso_organizations_invite() || CONFIG.sso_organizations_enabled() {
                    groups = groups_claim(email, &claims);
                }
            }
        }
    }

    Ok(AdditionnalClaims {
        role: roles.0,
        org_role: roles.1,
        groups,
    })
}

async fn decode_code_claims(code: &str, conn: &mut DbConn) -> ApiResult<(OIDCCode, OIDCState)> {
    match auth::decode_jwt::<OIDCCodeClaims>(code, SSO_JWT_ISSUER.to_string()) {
        Ok(code_claims) => match code_claims.code {
            OIDCCodeWrapper::Ok {
                state,
                code,
            } => Ok((code, state)),
            OIDCCodeWrapper::Error {
                state,
                error,
                error_description,
            } => {
                if let Err(err) = SsoNonce::delete(&state, conn).await {
                    error!("Failed to delete database sso_nonce using {state}: {err}")
                }
                err!(format!(
                    "SSO authorization failed: {error}, {}",
                    error_description.as_ref().unwrap_or(&String::new())
                ))
            }
        },
        Err(err) => err!(format!("Failed to decode code wrapper: {err}")),
    }
}

// During the 2FA flow we will
//  - retrieve the user information and then only discover he needs 2FA.
//  - second time we will rely on the `AC_CACHE` since the `code` has already been exchanged.
// The `nonce` will ensure that the user is authorized only once.
// We return only the `UserInformation` to force calling `redeem` to obtain the `refresh_token`.
pub async fn exchange_code(wrapped_code: &str, conn: &mut DbConn) -> ApiResult<UserInformation> {
    let (code, state) = decode_code_claims(wrapped_code, conn).await?;

    if let Some(authenticated_user) = AC_CACHE.get(&state) {
        return Ok(UserInformation {
            state,
            identifier: authenticated_user.identifier,
            email: authenticated_user.email,
            email_verified: authenticated_user.email_verified,
            user_name: authenticated_user.user_name,
        });
    }

    let oidc_code = AuthorizationCode::new(code.to_string());
    let client = Client::cached().await?;

    let nonce = match SsoNonce::find(&state, conn).await {
        None => err!(format!("Invalid state cannot retrieve nonce")),
        Some(nonce) => nonce,
    };

    let mut exchange = client.core_client.exchange_code(oidc_code);

    if CONFIG.sso_pkce() {
        match nonce.verifier {
            None => err!(format!("Missing verifier in the DB nonce table")),
            Some(secret) => exchange = exchange.set_pkce_verifier(PkceCodeVerifier::new(secret)),
        }
    }

    if CONFIG.sso_debug_force_fail_auth_code() {
        err!(format!("Exhange code {}", code.clone()));
    }

    match exchange.request_async(&client.http_client).await {
        Ok(token_response) => {
            let user_info = client.user_info(token_response.access_token().to_owned()).await?;
            let oidc_nonce = Nonce::new(nonce.nonce.clone());

            let id_token = match token_response.extra_fields().id_token() {
                None => err!("Token response did not contain an id_token"),
                Some(token) => token,
            };

            if CONFIG.sso_debug_tokens() {
                debug!("Id token: {}", id_token.to_string());
                debug!("Access token: {}", token_response.access_token().secret());
                debug!("Refresh token: {:?}", token_response.refresh_token().map(|t| t.secret()));
                debug!("Expiration time: {:?}", token_response.expires_in());
            }

            let id_claims = match id_token.claims(&client.vw_id_token_verifier(), &oidc_nonce) {
                Ok(claims) => claims,
                Err(err) => {
                    if CONFIG.sso_client_cache_expiration() > 0 {
                        CLIENT_CACHE.invalidate(&*CLIENT_CACHE_KEY);
                    }
                    err!(format!("Could not read id_token claims, {err}"));
                }
            };

            let email = match id_claims.email().or(user_info.email()) {
                None => err!("Neither id token nor userinfo contained an email"),
                Some(e) => e.to_string().to_lowercase(),
            };
            let email_verified = id_claims.email_verified().or(user_info.email_verified());

            let user_name = id_claims.preferred_username().map(|un| un.to_string());

            let additional_claims = additional_claims(&email, &id_token.to_string())?;

            if CONFIG.sso_roles_enabled() && !CONFIG.sso_roles_default_to_user() && additional_claims.role.is_none() {
                info!("User {email} failed to login due to missing/invalid role");
                err!(
                    "Invalid user role. Contact your administrator",
                    ErrorEvent {
                        event: EventType::UserFailedLogIn
                    }
                )
            }

            let refresh_token = token_response.refresh_token().map(|t| t.secret());
            if refresh_token.is_none() && CONFIG.sso_scopes_vec().contains(&"offline_access".to_string()) {
                error!("Scope offline_access is present but response contain no refresh_token");
            }

            let identifier = OIDCIdentifier::new(id_claims.issuer(), id_claims.subject());

            let authenticated_user = AuthenticatedUser {
                refresh_token: refresh_token.cloned(),
                access_token: token_response.access_token().secret().clone(),
                expires_in: token_response.expires_in(),
                identifier: identifier.clone(),
                email: email.clone(),
                email_verified,
                user_name: user_name.clone(),
                role: additional_claims.role,
                org_role: additional_claims.org_role,
                groups: additional_claims.groups,
            };

            debug!("Authentified user {:?}", authenticated_user);

            AC_CACHE.insert(state.clone(), authenticated_user);

            Ok(UserInformation {
                state,
                identifier,
                email,
                email_verified,
                user_name,
            })
        }
        Err(err) => err!(format!("Failed to contact token endpoint: {:?}", err)),
    }
}

// User has passed 2FA flow we can delete `nonce` and clear the cache.
pub async fn redeem(state: &OIDCState, conn: &mut DbConn) -> ApiResult<AuthenticatedUser> {
    if let Err(err) = SsoNonce::delete(state, conn).await {
        error!("Failed to delete database sso_nonce using {state}: {err}")
    }

    if let Some(au) = AC_CACHE.get(state) {
        AC_CACHE.invalidate(state);
        Ok(au)
    } else {
        err!("Failed to retrieve user info from sso cache")
    }
}

// We always return a refresh_token (with no refresh_token some secrets are not displayed in the web front).
// If there is no SSO refresh_token, we keep the access_token to be able to call user_info to check for validity
pub fn create_auth_tokens(
    device: &Device,
    user: &User,
    client_id: Option<String>,
    refresh_token: Option<String>,
    access_token: String,
    expires_in: Option<Duration>,
) -> ApiResult<AuthTokens> {
    if !CONFIG.sso_auth_only_not_session() {
        let now = Utc::now();

        let (ap_nbf, ap_exp) = match (insecure_decode::<BasicTokenClaims>("access_token", &access_token), expires_in) {
            (Ok(ap), _) => (ap.nbf(), ap.exp),
            (Err(_), Some(exp)) => (now.timestamp(), (now + exp).timestamp()),
            _ => err!("Non jwt access_token and empty expires_in"),
        };

        let access_claims =
            auth::LoginJwtClaims::new(device, user, ap_nbf, ap_exp, AuthMethod::Sso.scope_vec(), client_id, now);

        _create_auth_tokens(device, refresh_token, access_claims, access_token)
    } else {
        Ok(AuthTokens::new(device, user, AuthMethod::Sso, client_id))
    }
}

fn _create_auth_tokens(
    device: &Device,
    refresh_token: Option<String>,
    access_claims: auth::LoginJwtClaims,
    access_token: String,
) -> ApiResult<AuthTokens> {
    let (nbf, exp, token) = if let Some(rt) = refresh_token {
        match insecure_decode::<BasicTokenClaims>("refresh_token", &rt) {
            Err(_) => {
                let time_now = Utc::now();
                let exp = (time_now + *DEFAULT_REFRESH_VALIDITY).timestamp();
                debug!("Non jwt refresh_token (expiration set to {})", exp);
                (time_now.timestamp(), exp, TokenWrapper::Refresh(rt))
            }
            Ok(refresh_payload) => {
                debug!("Refresh_payload: {:?}", refresh_payload);
                (refresh_payload.nbf(), refresh_payload.exp, TokenWrapper::Refresh(rt))
            }
        }
    } else {
        debug!("No refresh_token present");
        (access_claims.nbf, access_claims.exp, TokenWrapper::Access(access_token))
    };

    let refresh_claims = auth::RefreshJwtClaims {
        nbf,
        exp,
        iss: auth::JWT_LOGIN_ISSUER.to_string(),
        sub: AuthMethod::Sso,
        device_token: device.refresh_token.clone(),
        token: Some(token),
    };

    Ok(AuthTokens {
        refresh_claims,
        access_claims,
    })
}

// This endpoint is called in two case
//  - the session is close to expiration we will try to extend it
//  - the user is going to make an action and we check that the session is still valid
pub async fn exchange_refresh_token(
    device: &Device,
    user: &User,
    client_id: Option<String>,
    refresh_claims: auth::RefreshJwtClaims,
) -> ApiResult<AuthTokens> {
    let exp = refresh_claims.exp;
    match refresh_claims.token {
        Some(TokenWrapper::Refresh(refresh_token)) => {
            let rt = RefreshToken::new(refresh_token);

            let client = Client::cached().await?;

            let token_response =
                match client.core_client.exchange_refresh_token(&rt).request_async(&client.http_client).await {
                    Err(err) => err!(format!("Request to exchange_refresh_token endpoint failed: {:?}", err)),
                    Ok(token_response) => token_response,
                };

            // Use new refresh_token if returned
            let rolled_refresh_token =
                token_response.refresh_token().map(|token| token.secret()).unwrap_or(rt.secret());

            create_auth_tokens(
                device,
                user,
                client_id,
                Some(rolled_refresh_token.clone()),
                token_response.access_token().secret().clone(),
                token_response.expires_in(),
            )
        }
        Some(TokenWrapper::Access(access_token)) => {
            let now = Utc::now();
            let exp_limit = (now + *BW_EXPIRATION).timestamp();

            if exp < exp_limit {
                err_silent!("Access token is close to expiration but we have no refresh token")
            }

            let client = Client::cached().await?;
            match client.user_info(AccessToken::new(access_token.clone())).await {
                Err(err) => {
                    err_silent!(format!("Failed to retrieve user info, token has probably been invalidated: {err}"))
                }
                Ok(_) => {
                    let access_claims = auth::LoginJwtClaims::new(
                        device,
                        user,
                        now.timestamp(),
                        exp,
                        AuthMethod::Sso.scope_vec(),
                        client_id,
                        now,
                    );
                    _create_auth_tokens(device, None, access_claims, access_token)
                }
            }
        }
        None => err!("No token present while in SSO"),
    }
}

pub async fn sync_organizations(
    user: &User,
    sso_user: &AuthenticatedUser,
    device: &Device,
    ip: &ClientIp,
    conn: &mut DbConn,
) -> ApiResult<()> {
    if (CONFIG.sso_organizations_invite() || CONFIG.sso_organizations_enabled())
        && sso_user.org_role != Some(UserOrgRole::OrgNoSync)
    {
        let id_mapping = CONFIG.sso_organizations_id_mapping_map();
        let user_groups = &sso_user.groups;

        debug!("Organization and groups sync for user {:} with {:?}", user.email, user_groups);

        let mut allow_revoking = CONFIG.sso_organizations_revocation();

        let orgs = if id_mapping.is_empty() {
            let identifiers = if CONFIG.org_groups_enabled() && CONFIG.sso_organizations_groups_enabled() {
                parse_user_groups(user_groups)
            } else {
                user_groups.iter().map(|g| (g.clone(), None)).collect()
            };

            let org_groups = Organization::find_mapped_orgs_and_groups(identifiers.clone(), conn)
                .await
                .into_iter()
                .filter(|(_, _, _, group_id)| {
                    !group_id.is_some() || (CONFIG.org_groups_enabled() && CONFIG.sso_organizations_groups_enabled())
                })
                .collect::<Vec<(String, Option<String>, Organization, Option<GroupId>)>>();

            allow_revoking = check_orgs_groups(&identifiers, &org_groups)? && allow_revoking;

            let mut res: HashMap<OrganizationId, (Organization, HashSet<GroupId>)> = HashMap::new();
            for (_, _, org, group_id) in org_groups {
                let entry = res.entry(org.uuid.clone()).or_insert_with(|| (org, HashSet::new()));
                if let Some(gi) = group_id {
                    entry.1.insert(gi);
                }
            }
            res
        } else {
            warn!("Using deprecated SSO_ORGANIZATIONS_ID_MAPPING, will be removed in next release");
            use itertools::Itertools; // TODO: Remove from cargo.toml

            let (names, uuids) = user_groups
                .iter()
                .flat_map(|group| match id_mapping.get(group) {
                    Some(e) => Some(e.clone()),
                    None => {
                        warn!("Missing organization mapping for {group}");
                        None
                    }
                })
                .partition_map(std::convert::identity);

            let orgs = Organization::find_by_uuids_or_names(&uuids, &names, conn).await;

            if user_groups.len() != orgs.len() {
                let org_names: Vec<&String> = orgs.iter().map(|o| &o.name).collect();
                warn!(
                    "Failed to match all groups ({:?}) to organizations ({:?}) with mapping ({:?}), will not revoke",
                    user_groups, org_names, id_mapping
                );

                allow_revoking = false
            }

            orgs.into_iter()
                .map(|o| (o.uuid.clone(), (o, HashSet::new())))
                .collect::<HashMap<OrganizationId, (Organization, HashSet<GroupId>)>>()
        };

        sync_orgs_and_role(user, sso_user, device, ip, orgs, allow_revoking, conn).await?;
    }

    Ok(())
}

fn check_orgs_groups(
    identifiers: &Vec<(String, Option<String>)>,
    org_groups: &Vec<(String, Option<String>, Organization, Option<GroupId>)>,
) -> ApiResult<bool> {
    let mut allow_revoking = true;

    let mut check_mapping: HashMap<(&String, &Option<String>), i32> = HashMap::new();
    for (identifier, group_name, _, _) in org_groups {
        *check_mapping.entry((identifier, group_name)).or_default() += 1;
    }
    if check_mapping.len() != identifiers.len() || check_mapping.values().any(|v| *v != 1) {
        allow_revoking = false;
        warn!("Failed to correctly match user groups, revoking will be disabled");

        for (id, group) in identifiers {
            let count = check_mapping.remove(&(id, group)).unwrap_or(0);
            match count {
                0 => warn!("Identifier ({} - {:?})  returned no match", id, group),
                1 => (),
                c => warn!("Identifier ({} - {:?}) returned {} match", id, group, c),
            }
        }

        if check_mapping.values().any(|v| *v > 1) {
            err_silent!("mapping with multiple match, sync will not proceed");
        }
    }

    Ok(allow_revoking)
}

async fn sync_orgs_and_role(
    user: &User,
    sso_user: &AuthenticatedUser,
    device: &Device,
    ip: &ClientIp,
    mut orgs: HashMap<OrganizationId, (Organization, HashSet<GroupId>)>,
    allow_revoking: bool,
    conn: &mut DbConn,
) -> ApiResult<()> {
    let acting_user: UserId = ACTING_AUTO_ENROLL_USER.into();
    let provider_role = sso_user.org_role.as_ref().map(|or| or.membership_type());
    let org_collections: Vec<CollectionData> = vec![];
    let user_org_groups: Vec<GroupId> = vec![];

    debug!(
        "Matched organizations {:?}",
        orgs.iter().map(|(_, (org, groups))| (&org.name, groups)).collect::<Vec<(&String, &HashSet<GroupId>)>>()
    );

    for mut mbs in Membership::find_any_state_by_user(&user.uuid, conn).await {
        match orgs.remove(&mbs.org_uuid) {
            Some((_, groups)) => {
                if let Some(new_type) = provider_role.filter(|r| mbs.atype != *r as i32) {
                    let er = organization_logic::set_membership_type(
                        &acting_user,
                        device,
                        ip,
                        &mut mbs,
                        new_type,
                        true,
                        conn,
                    )
                    .await;

                    if let Err(e) = er {
                        error!("Failed to set_membership_type {}: {}", sso_user.email, e);
                    }
                }
                if mbs.is_revoked() {
                    if let Err(er) = organization_logic::restore_member(&acting_user, device, ip, &mut mbs, conn).await
                    {
                        error!("Failed to restore_member {}: {}", sso_user.email, er);
                    }
                }

                sync_org_groups(&acting_user, user, device, ip, &mbs, groups, allow_revoking, conn).await?;
            }
            None if allow_revoking => {
                if let Err(er) = organization_logic::revoke_member(&acting_user, device, ip, mbs, conn).await {
                    error!("Failed to restore_member {}: {}", sso_user.email, er);
                }
            }
            None => {}
        }
    }

    let new_user_role = provider_role.unwrap_or(MembershipType::User);
    for (org, groups) in orgs.into_values() {
        info!("Invitation to {} organization sent to {}", org.name, user.email);
        let mbs = organization_logic::invite(
            &acting_user,
            device,
            ip,
            &org,
            user,
            new_user_role,
            &user_org_groups,
            new_user_role > MembershipType::User || CONFIG.sso_organizations_all_collections(),
            &org_collections,
            org.billing_email.clone(),
            true,
            conn,
        )
        .await?;

        sync_org_groups(&acting_user, user, device, ip, &mbs, groups, allow_revoking, conn).await?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn sync_org_groups(
    acting_user: &UserId,
    user: &User,
    device: &Device,
    ip: &ClientIp,
    member: &Membership,
    mut groups: HashSet<GroupId>,
    allow_revoking: bool,
    conn: &mut DbConn,
) -> ApiResult<()> {
    for gu in GroupUser::find_by_member(&member.uuid, conn).await {
        if !groups.remove(&gu.groups_uuid) && allow_revoking {
            debug!("Removing user {} from organization {} group {}", user.email, member.org_uuid, &gu.groups_uuid);

            organization_logic::delete_group_user(
                acting_user,
                device,
                ip,
                &member.org_uuid,
                &member.uuid,
                &gu.groups_uuid,
                conn,
            )
            .await?;
        }
    }

    for group_id in groups {
        debug!("Adding user {} to organization {} group {}", user.email, member.org_uuid, group_id);

        organization_logic::add_group_user(
            acting_user,
            device,
            ip,
            &member.org_uuid,
            member.uuid.clone(),
            &group_id,
            conn,
        )
        .await?;
    }

    Ok(())
}

fn parse_user_groups(raw_groups: &Vec<String>) -> Vec<(String, Option<String>)> {
    use std::path::Path;

    let root = Path::new("/");
    let mut orgs: HashMap<String, HashSet<String>> = HashMap::new();

    for rg in raw_groups {
        let p = root.join(Path::new(rg));

        let (org, group) = match (p.parent().and_then(|o| o.to_str()), p.file_name().and_then(|g| g.to_str())) {
            (None | Some("/"), Some(file_name)) => (Some(file_name.to_string()), None),
            (Some(parent), file_name) => {
                let mut org = parent.to_string();
                org.remove(0);

                (Some(org), file_name.map(|g| g.to_string()))
            }
            (None, None) => (None, None),
        };

        if let Some(o) = org {
            let entry = orgs.entry(o).or_default();
            if let Some(g) = group {
                entry.insert(g);
            }
        }
    }

    let mut res = Vec::new();
    for (key, groups) in orgs {
        res.push((key.clone(), None));
        for g in groups {
            res.push((key.clone(), Some(g)));
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_user_groups() {
        let raw_groups = vec![
            "simpleorg1".to_string(),
            "/simpleorg2".to_string(),
            "/simpleorg3/".to_string(),
            "simpleorg4/group41".to_string(),
            "/simpleorg5/group51/".to_string(),
            "org/withslash1/group61".to_string(),
            "org/withslash2/group71/".to_string(),
            "/simpleorg1/duplicate11".to_string(),
            "/simpleorg1/duplicate12".to_string(),
        ];

        let mut res = parse_user_groups(&raw_groups);
        res.sort();

        assert_eq!(
            res,
            vec![
                ("org/withslash1".to_string(), None),
                ("org/withslash1".to_string(), Some("group61".to_string())),
                ("org/withslash2".to_string(), None),
                ("org/withslash2".to_string(), Some("group71".to_string())),
                ("simpleorg1".to_string(), None),
                ("simpleorg1".to_string(), Some("duplicate11".to_string())),
                ("simpleorg1".to_string(), Some("duplicate12".to_string())),
                ("simpleorg2".to_string(), None),
                ("simpleorg3".to_string(), None),
                ("simpleorg4".to_string(), None),
                ("simpleorg4".to_string(), Some("group41".to_string())),
                ("simpleorg5".to_string(), None),
                ("simpleorg5".to_string(), Some("group51".to_string())),
            ]
        );
    }
}
