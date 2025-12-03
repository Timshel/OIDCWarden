use std::{sync::LazyLock, time::Duration};

use chrono::Utc;
use derive_more::{AsRef, Deref, Display, From, Into};
use regex::Regex;
use serde::de::DeserializeOwned;
use serde_with::{serde_as, DefaultOnError};
use std::collections::{HashMap, HashSet};
use url::Url;

use crate::{
    api::core::organizations::CollectionData,
    api::ApiResult,
    auth,
    auth::{AuthMethod, AuthTokens, ClientIp, TokenWrapper, BW_EXPIRATION, DEFAULT_REFRESH_VALIDITY},
    business::organization_logic,
    db::{
        models::{
            Collection, Device, EventType, GroupId, GroupUser, Membership, MembershipType, OIDCAuthenticatedUser,
            OIDCCodeWrapper, Organization, OrganizationId, SsoAuth, SsoUser, User, UserId,
        },
        DbConn,
    },
    sso_client::{AllAdditionalClaims, Client},
    CONFIG,
};

pub static FAKE_IDENTIFIER: &str = "VW_DUMMY_IDENTIFIER_FOR_OIDC";
pub const ACTING_AUTO_ENROLL_USER: &str = "oidcwarden-auto-00000-000000000000";

static SSO_JWT_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|sso", CONFIG.domain_origin()));

pub static SSO_AUTH_EXPIRATION: LazyLock<chrono::Duration> =
    LazyLock::new(|| chrono::TimeDelta::try_minutes(10).unwrap());

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
    Into,
)]
#[deref(forward)]
#[into(owned)]
pub struct OIDCCodeChallenge(String);

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
    Into,
)]
#[deref(forward)]
#[into(owned)]
pub struct OIDCCodeVerifier(String);

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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BasicTokenClaims {
    iat: Option<i64>,
    nbf: Option<i64>,
    exp: i64,
}

#[derive(Deserialize)]
struct BasicTokenClaimsValidation {
    exp: u64,
    iss: String,
}

impl BasicTokenClaims {
    fn nbf(&self) -> i64 {
        self.nbf.or(self.iat).unwrap_or_else(|| Utc::now().timestamp())
    }
}

fn decode_token_claims(token_name: &str, token: &str) -> ApiResult<BasicTokenClaims> {
    // We need to manually validate this token, since `insecure_decode` does not do this
    match jsonwebtoken::dangerous::insecure_decode::<BasicTokenClaimsValidation>(token) {
        Ok(btcv) => {
            let now = jsonwebtoken::get_current_timestamp();
            let validate_claim = btcv.claims;
            // Validate the exp in the claim with a leeway of 60 seconds, same as jsonwebtoken does
            if validate_claim.exp < now - 60 {
                err_silent!(format!("Expired Signature for base token claim from {token_name}"))
            }
            if validate_claim.iss.ne(&CONFIG.sso_authority()) {
                err_silent!(format!("Invalid Issuer for base token claim from {token_name}"))
            }

            // All is validated and ok, lets decode again using the wanted struct
            let btc = jsonwebtoken::dangerous::insecure_decode::<BasicTokenClaims>(token).unwrap();
            Ok(btc.claims)
        }
        Err(err) => err_silent!(format!("Failed to decode basic token claims from {token_name}: {err}")),
    }
}

pub fn decode_state(base64_state: &str) -> ApiResult<OIDCState> {
    let state = match data_encoding::BASE64.decode(base64_state.as_bytes()) {
        Ok(vec) => match String::from_utf8(vec) {
            Ok(valid) => OIDCState(valid),
            Err(_) => err!(format!("Invalid utf8 chars in {base64_state} after base64 decoding")),
        },
        Err(_) => err!(format!("Failed to decode {base64_state} using base64")),
    };

    Ok(state)
}

// redirect_uri from: https://github.com/bitwarden/server/blob/main/src/Identity/IdentityServer/ApiClient.cs
pub async fn authorize_url(
    state: OIDCState,
    client_challenge: OIDCCodeChallenge,
    client_id: &str,
    raw_redirect_uri: &str,
    conn: DbConn,
) -> ApiResult<Url> {
    let redirect_uri = match client_id {
        "web" | "browser" => format!("{}/sso-connector.html", CONFIG.domain()),
        "desktop" | "mobile" => "bitwarden://sso-callback".to_string(),
        "cli" => {
            let port_regex = Regex::new(r"^http://localhost:([0-9]{4})$").unwrap();
            match port_regex.captures(raw_redirect_uri).and_then(|captures| captures.get(1).map(|c| c.as_str())) {
                Some(port) => format!("http://localhost:{port}"),
                None => err!("Failed to extract port number"),
            }
        }
        _ => err!(format!("Unsupported client {client_id}")),
    };

    let (auth_url, sso_auth) = Client::authorize_url(state, client_challenge, redirect_uri).await?;
    sso_auth.save(&conn).await?;
    Ok(auth_url)
}

#[derive(Debug)]
struct AdditionalClaims {
    role: Option<UserRole>,
    org_role: Option<UserOrgRole>,
    groups: Option<Vec<String>>,
}

impl AdditionalClaims {
    pub fn is_admin(&self) -> bool {
        self.role.as_ref().is_some_and(|x| x == &UserRole::Admin)
    }
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::enum_variant_names)]
pub enum UserOrgRole {
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
        OIDCIdentifier(format!("{issuer}/{subject}"))
    }
}

// Errors are logged but will return None
// Return the top most defined Role (https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html#derivable)
fn role_claim<T: DeserializeOwned + Ord>(email: &str, token: &serde_json::Value, source: &str) -> Option<T> {
    use crate::serde::Deserialize;
    if let Some(json_roles) = token.pointer(&CONFIG.sso_roles_token_path()) {
        match UserRoles::<T>::deserialize(json_roles) {
            Ok(UserRoles(mut roles)) => {
                roles.sort();
                roles.into_iter().find(|r| r.is_some()).flatten()
            }
            Err(err) => {
                debug!("Failed to parse {email} roles from {source}: {err}");
                None
            }
        }
    } else {
        debug!("No roles in {email} {source} at {}", &CONFIG.sso_roles_token_path());
        None
    }
}

// Errors are logged but will return an empty Vec
fn groups_claim(email: &str, token: &serde_json::Value, source: &str) -> Option<Vec<String>> {
    if let Some(json_groups) = token.pointer(&CONFIG.sso_organizations_token_path()) {
        match serde_json::from_value::<Vec<String>>(json_groups.clone()) {
            Ok(groups) => Some(groups),
            Err(err) => {
                error!("Failed to parse ({email}) groups from {source}: {err}");
                None
            }
        }
    } else {
        debug!("No groups in {email} {source} at {}", &CONFIG.sso_organizations_token_path());
        None
    }
}

// All claims are read as Value.
fn additional_claims(email: &str, sources: Vec<(&AllAdditionalClaims, &str)>) -> ApiResult<AdditionalClaims> {
    let mut role: Option<UserRole> = None;
    let mut org_role: Option<UserOrgRole> = None;
    let mut groups = None;

    if CONFIG.sso_roles_enabled() || CONFIG.sso_organizations_enabled() {
        for (ac, source) in sources {
            if CONFIG.sso_roles_enabled() {
                role = role.or_else(|| role_claim(email, &ac.claims, source))
            }

            if CONFIG.sso_organizations_enabled() {
                org_role = org_role.or_else(|| role_claim(email, &ac.claims, source));
                groups = groups.or_else(|| groups_claim(email, &ac.claims, source));
            }
        }
    }

    Ok(AdditionalClaims {
        role,
        org_role,
        groups,
    })
}

// During the 2FA flow we will
//  - retrieve the user information and then only discover he needs 2FA.
//  - second time we will rely on `SsoAuth.auth_response` since the `code` has already been exchanged.
// The `SsoAuth` will ensure that the user is authorized only once.
pub async fn exchange_code(
    state: &OIDCState,
    client_verifier: OIDCCodeVerifier,
    conn: &DbConn,
) -> ApiResult<(SsoAuth, OIDCAuthenticatedUser)> {
    use openidconnect::OAuth2TokenResponse;

    let mut sso_auth = match SsoAuth::find(state, conn).await {
        None => err!(format!("Invalid state cannot retrieve sso auth")),
        Some(sso_auth) => sso_auth,
    };

    if let Some(authenticated_user) = sso_auth.auth_response.clone() {
        return Ok((sso_auth, authenticated_user));
    }

    let code = match sso_auth.code_response.clone() {
        Some(OIDCCodeWrapper::Ok {
            code,
        }) => code.clone(),
        Some(OIDCCodeWrapper::Error {
            error,
            error_description,
        }) => {
            sso_auth.delete(conn).await?;
            err!(format!("SSO authorization failed: {error}, {}", error_description.as_ref().unwrap_or(&String::new())))
        }
        None => {
            sso_auth.delete(conn).await?;
            err!("Missing authorization provider return");
        }
    };

    let client = Client::cached().await?;
    let (token_response, id_claims) = client.exchange_code(code, client_verifier, &sso_auth).await?;

    let user_info = client.user_info(token_response.access_token().clone()).await?;

    let email = match id_claims.email().or(user_info.email()) {
        None => err!("Neither id token nor userinfo contained an email"),
        Some(e) => e.to_string().to_lowercase(),
    };

    let email_verified = id_claims.email_verified().or(user_info.email_verified());

    let user_name = id_claims.preferred_username().map(|un| un.to_string());

    let additional_claims = additional_claims(
        &email,
        vec![(id_claims.additional_claims(), "id_token"), (user_info.additional_claims(), "user_info")],
    )?;

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

    let authenticated_user = OIDCAuthenticatedUser {
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

    debug!("Authenticated user {authenticated_user:?}");
    sso_auth.auth_response = Some(authenticated_user.clone());
    sso_auth.updated_at = Utc::now().naive_utc();
    sso_auth.save(conn).await?;

    Ok((sso_auth, authenticated_user))
}

// User has passed 2FA flow we can delete auth info from database
#[allow(clippy::too_many_arguments)]
pub async fn redeem(
    device: &Device,
    user: &User,
    ip: &ClientIp,
    client_id: Option<String>,
    sso_user: Option<SsoUser>,
    sso_auth: SsoAuth,
    auth_user: OIDCAuthenticatedUser,
    conn: &DbConn,
) -> ApiResult<AuthTokens> {
    sso_auth.delete(conn).await?;

    if sso_user.is_none() {
        let user_sso = SsoUser {
            user_uuid: user.uuid.clone(),
            identifier: auth_user.identifier.clone(),
        };
        user_sso.save(conn).await?;
    }

    if let Err(err) = sync_organizations(user, device, ip, &auth_user.org_role, &auth_user.groups, conn).await {
        error!("Failure during sso organization sync: {err}");
    }

    let is_admin = auth_user.is_admin();
    create_auth_tokens(
        device,
        user,
        client_id,
        auth_user.refresh_token,
        auth_user.access_token,
        auth_user.expires_in,
        is_admin,
    )
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
    is_admin: bool,
) -> ApiResult<AuthTokens> {
    if !CONFIG.sso_auth_only_not_session() {
        let now = Utc::now();

        let (ap_nbf, ap_exp) = match (decode_token_claims("access_token", &access_token), expires_in) {
            (Ok(ap), _) => (ap.nbf(), ap.exp),
            (Err(_), Some(exp)) => (now.timestamp(), (now + exp).timestamp()),
            _ => err!("Non jwt access_token and empty expires_in"),
        };

        let access_claims =
            auth::LoginJwtClaims::new(device, user, ap_nbf, ap_exp, AuthMethod::Sso.scope_vec(), client_id, now);

        _create_auth_tokens(device, refresh_token, access_claims, access_token, is_admin)
    } else {
        Ok(AuthTokens::new(device, user, AuthMethod::Sso, client_id))
    }
}

fn _create_auth_tokens(
    device: &Device,
    refresh_token: Option<String>,
    access_claims: auth::LoginJwtClaims,
    access_token: String,
    is_admin: bool,
) -> ApiResult<AuthTokens> {
    let (nbf, exp, token) = if let Some(rt) = refresh_token {
        match decode_token_claims("refresh_token", &rt) {
            Err(_) => {
                let time_now = Utc::now();
                let exp = (time_now + *DEFAULT_REFRESH_VALIDITY).timestamp();
                debug!("Non jwt refresh_token (expiration set to {exp})");
                (time_now.timestamp(), exp, TokenWrapper::Refresh(rt))
            }
            Ok(refresh_payload) => {
                debug!("Refresh_payload: {refresh_payload:?}");
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
        is_admin,
    })
}

// This endpoint is called in two case
//  - the session is close to expiration we will try to extend it
//  - the user is going to make an action and we check that the session is still valid
pub async fn exchange_refresh_token(
    user: &User,
    device: &Device,
    ip: &ClientIp,
    client_id: Option<String>,
    refresh_claims: auth::RefreshJwtClaims,
    conn: &DbConn,
) -> ApiResult<AuthTokens> {
    let exp = refresh_claims.exp;
    match refresh_claims.token {
        Some(TokenWrapper::Refresh(refresh_token)) => {
            let client = Client::cached().await?;
            let mut is_admin = false;

            // Use new refresh_token if returned
            let (new_refresh_token, access_token, expires_in) =
                client.exchange_refresh_token(refresh_token.clone()).await?;

            if CONFIG.sso_sync_on_refresh() && (CONFIG.sso_roles_enabled() || CONFIG.sso_organizations_enabled()) {
                let user_info = client.user_info(access_token.clone()).await?;
                let ac = additional_claims(&user.email, vec![(user_info.additional_claims(), "user_info")])?;
                is_admin = CONFIG.sso_roles_enabled() && ac.is_admin();
                if CONFIG.sso_organizations_enabled() {
                    sync_organizations(user, device, ip, &ac.org_role, &ac.groups, conn).await?;
                }
            }

            create_auth_tokens(
                device,
                user,
                client_id,
                new_refresh_token.or(Some(refresh_token)),
                access_token.secret().clone(),
                expires_in,
                is_admin,
            )
        }
        Some(TokenWrapper::Access(access_token)) => {
            let now = Utc::now();
            let exp_limit = (now + *BW_EXPIRATION).timestamp();

            if exp < exp_limit {
                err_silent!("Access token is close to expiration but we have no refresh token")
            }

            Client::check_validity(access_token.clone()).await?;

            let access_claims = auth::LoginJwtClaims::new(
                device,
                user,
                now.timestamp(),
                exp,
                AuthMethod::Sso.scope_vec(),
                client_id,
                now,
            );

            _create_auth_tokens(device, None, access_claims, access_token, false)
        }
        None => err!("No token present while in SSO"),
    }
}

async fn sync_organizations(
    user: &User,
    device: &Device,
    ip: &ClientIp,
    org_role: &Option<UserOrgRole>,
    user_groups: &Option<Vec<String>>,
    conn: &DbConn,
) -> ApiResult<()> {
    let groups = match (org_role, user_groups) {
        (Some(UserOrgRole::OrgNoSync), _) => return Ok(()),
        (_, Some(g)) if CONFIG.sso_organizations_enabled() => g,
        _ => return Ok(()),
    };

    debug!("Organization and groups sync for user {:} with {:?}", user.email, groups);

    let mut allow_revoking = CONFIG.sso_organizations_revocation();

    let identifiers = if CONFIG.org_groups_enabled() {
        parse_user_groups(groups)
    } else {
        groups.iter().map(|g| (g.clone(), None)).collect()
    };

    let org_groups = Organization::find_mapped_orgs_and_groups(identifiers.clone(), conn)
        .await
        .into_iter()
        .filter(|(_, _, _, group_id)| !group_id.is_some() || (CONFIG.org_groups_enabled()))
        .collect::<Vec<(String, Option<String>, Organization, Option<GroupId>)>>();

    allow_revoking = check_orgs_groups(&identifiers, &org_groups)? && allow_revoking;

    let mut orgs: HashMap<OrganizationId, (Organization, HashSet<GroupId>)> = HashMap::new();
    for (_, _, org, group_id) in org_groups {
        let entry = orgs.entry(org.uuid.clone()).or_insert_with(|| (org, HashSet::new()));
        if let Some(gi) = group_id {
            entry.1.insert(gi);
        }
    }

    sync_orgs_and_role(user, device, ip, org_role, orgs, allow_revoking, conn).await
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
                0 => warn!("Identifier ({id} - {group:?})  returned no match"),
                1 => (),
                c => warn!("Identifier ({id} - {group:?}) returned {c} match"),
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
    device: &Device,
    ip: &ClientIp,
    org_role: &Option<UserOrgRole>,
    mut orgs: HashMap<OrganizationId, (Organization, HashSet<GroupId>)>,
    allow_revoking: bool,
    conn: &DbConn,
) -> ApiResult<()> {
    let acting_user: UserId = ACTING_AUTO_ENROLL_USER.into();
    let provider_role = org_role.as_ref().map(|or| or.membership_type());
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
                        error!("Failed to set_membership_type {}: {}", user.email, e);
                    }
                }
                if mbs.is_revoked() {
                    if let Err(er) = organization_logic::restore_member(&acting_user, device, ip, &mut mbs, conn).await
                    {
                        error!("Failed to restore_member {}: {}", user.email, er);
                    }
                }

                sync_org_groups(&acting_user, user, device, ip, &mbs, groups, allow_revoking, conn).await?;
            }
            None if allow_revoking => {
                if let Err(er) = organization_logic::revoke_member(&acting_user, device, ip, mbs, conn).await {
                    error!("Failed to restore_member {}: {}", user.email, er);
                }
            }
            None => {}
        }
    }

    let new_user_role = provider_role.unwrap_or(MembershipType::User);
    for (org, groups) in orgs.into_values() {
        let org_collections: Vec<CollectionData> =
            if new_user_role == MembershipType::User && CONFIG.sso_organizations_all_collections() {
                Collection::find_by_organization(&org.uuid, conn)
                    .await
                    .into_iter()
                    .map(|col| CollectionData {
                        id: col.uuid,
                        read_only: true,
                        hide_passwords: false,
                        manage: false,
                    })
                    .collect()
            } else {
                vec![]
            };

        info!("Invitation to {} organization sent to {}", org.name, user.email);
        let mbs = organization_logic::invite(
            &acting_user,
            device,
            ip,
            &org,
            user,
            new_user_role,
            &user_org_groups,
            new_user_role > MembershipType::User,
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
    conn: &DbConn,
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
