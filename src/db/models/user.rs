use chrono::{NaiveDateTime, TimeDelta, Utc};
use derive_more::{AsRef, Deref, Display, From};
use serde_json::Value;

use super::{
    Cipher, Device, EmergencyAccess, Favorite, Folder, Membership, MembershipType, TwoFactor, TwoFactorIncomplete,
};
use crate::{
    api::EmptyResult,
    crypto,
    db::models::DeviceId,
    db::DbConn,
    error::MapResult,
    sso::OIDCIdentifier,
    util::{format_date, get_uuid, retry},
    CONFIG,
};
use macros::UuidFromParam;

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset, Selectable)]
    #[diesel(table_name = users)]
    #[diesel(treat_none_as_null = true)]
    #[diesel(primary_key(uuid))]
    pub struct User {
        pub uuid: UserId,
        pub enabled: bool,
        pub created_at: NaiveDateTime,
        pub updated_at: NaiveDateTime,
        pub verified_at: Option<NaiveDateTime>,
        pub last_verifying_at: Option<NaiveDateTime>,
        pub login_verify_count: i32,

        pub email: String,
        pub email_new: Option<String>,
        pub email_new_token: Option<String>,
        pub name: String,

        pub password_hash: Vec<u8>,
        pub salt: Vec<u8>,
        pub password_iterations: i32,
        pub password_hint: Option<String>,

        pub akey: String,
        pub private_key: Option<String>,
        pub public_key: Option<String>,

        #[diesel(column_name = "totp_secret")] // Note, this is only added to the UserDb structs, not to User
        _totp_secret: Option<String>,
        pub totp_recover: Option<String>,

        pub security_stamp: String,
        pub stamp_exception: Option<String>,

        pub equivalent_domains: String,
        pub excluded_globals: String,

        pub client_kdf_type: i32,
        pub client_kdf_iter: i32,
        pub client_kdf_memory: Option<i32>,
        pub client_kdf_parallelism: Option<i32>,

        pub api_key: Option<String>,

        pub avatar_color: Option<String>,

        pub external_id: Option<String>, // Todo: Needs to be removed in the future, this is not used anymore.
    }

    #[derive(Identifiable, Queryable, Insertable)]
    #[diesel(table_name = invitations)]
    #[diesel(primary_key(email))]
    pub struct Invitation {
        pub email: String,
    }

    #[derive(Identifiable, Queryable, Insertable, Selectable)]
    #[diesel(table_name = sso_users)]
    #[diesel(primary_key(user_uuid))]
    pub struct SsoUser {
        pub user_uuid: UserId,
        pub identifier: OIDCIdentifier,
    }
}

pub enum UserKdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}

enum UserStatus {
    Enabled = 0,
    Invited = 1,
    _Disabled = 2,
}

#[derive(Serialize, Deserialize)]
pub struct UserStampException {
    pub routes: Vec<String>,
    pub security_stamp: String,
    pub expire: i64,
}

/// Local methods
impl User {
    pub const CLIENT_KDF_TYPE_DEFAULT: i32 = UserKdfType::Pbkdf2 as i32;
    pub const CLIENT_KDF_ITER_DEFAULT: i32 = 600_000;

    pub fn new(email: String, name: Option<String>) -> Self {
        let now = Utc::now().naive_utc();
        let email = email.to_lowercase();

        Self {
            uuid: UserId(get_uuid()),
            enabled: true,
            created_at: now,
            updated_at: now,
            verified_at: None,
            last_verifying_at: None,
            login_verify_count: 0,
            name: name.unwrap_or(email.clone()),
            email,
            akey: String::new(),
            email_new: None,
            email_new_token: None,

            password_hash: Vec::new(),
            salt: crypto::get_random_bytes::<64>().to_vec(),
            password_iterations: CONFIG.password_iterations(),

            security_stamp: get_uuid(),
            stamp_exception: None,

            password_hint: None,
            private_key: None,
            public_key: None,

            _totp_secret: None,
            totp_recover: None,

            equivalent_domains: "[]".to_string(),
            excluded_globals: "[]".to_string(),

            client_kdf_type: Self::CLIENT_KDF_TYPE_DEFAULT,
            client_kdf_iter: Self::CLIENT_KDF_ITER_DEFAULT,
            client_kdf_memory: None,
            client_kdf_parallelism: None,

            api_key: None,

            avatar_color: None,

            external_id: None, // Todo: Needs to be removed in the future, this is not used anymore.
        }
    }

    pub fn check_valid_password(&self, password: &str) -> bool {
        crypto::verify_password_hash(
            password.as_bytes(),
            &self.salt,
            &self.password_hash,
            self.password_iterations as u32,
        )
    }

    pub fn check_valid_recovery_code(&self, recovery_code: &str) -> bool {
        if let Some(ref totp_recover) = self.totp_recover {
            crypto::ct_eq(recovery_code, totp_recover.to_lowercase())
        } else {
            false
        }
    }

    pub fn check_valid_api_key(&self, key: &str) -> bool {
        matches!(self.api_key, Some(ref api_key) if crypto::ct_eq(api_key, key))
    }

    /// Set the password hash generated
    /// And resets the security_stamp. Based upon the allow_next_route the security_stamp will be different.
    ///
    /// # Arguments
    ///
    /// * `password` - A str which contains a hashed version of the users master password.
    /// * `new_key` - A String  which contains the new aKey value of the users master password.
    /// * `allow_next_route` - A Option<Vec<String>> with the function names of the next allowed (rocket) routes.
    ///   These routes are able to use the previous stamp id for the next 2 minutes.
    ///   After these 2 minutes this stamp will expire.
    ///
    pub fn set_password(
        &mut self,
        password: &str,
        new_key: Option<String>,
        reset_security_stamp: bool,
        allow_next_route: Option<Vec<String>>,
    ) {
        self.password_hash = crypto::hash_password(password.as_bytes(), &self.salt, self.password_iterations as u32);

        if let Some(route) = allow_next_route {
            self.set_stamp_exception(route);
        }

        if let Some(new_key) = new_key {
            self.akey = new_key;
        }

        if reset_security_stamp {
            self.reset_security_stamp()
        }
    }

    pub fn reset_security_stamp(&mut self) {
        self.security_stamp = get_uuid();
    }

    /// Set the stamp_exception to only allow a subsequent request matching a specific route using the current security-stamp.
    ///
    /// # Arguments
    /// * `route_exception` - A Vec<String> with the function names of the next allowed (rocket) routes.
    ///   These routes are able to use the previous stamp id for the next 2 minutes.
    ///   After these 2 minutes this stamp will expire.
    ///
    pub fn set_stamp_exception(&mut self, route_exception: Vec<String>) {
        let stamp_exception = UserStampException {
            routes: route_exception,
            security_stamp: self.security_stamp.clone(),
            expire: (Utc::now() + TimeDelta::try_minutes(2).unwrap()).timestamp(),
        };
        self.stamp_exception = Some(serde_json::to_string(&stamp_exception).unwrap_or_default());
    }

    /// Resets the stamp_exception to prevent re-use of the previous security-stamp
    pub fn reset_stamp_exception(&mut self) {
        self.stamp_exception = None;
    }
}

/// Database methods
impl User {
    pub async fn to_json(&self, conn: &mut DbConn) -> Value {
        let mut orgs_json = Vec::new();
        for c in Membership::find_confirmed_by_user(&self.uuid, conn).await {
            orgs_json.push(c.to_json(conn).await);
        }

        let twofactor_enabled = !TwoFactor::find_by_user(&self.uuid, conn).await.is_empty();

        // TODO: Might want to save the status field in the DB
        let status = if self.password_hash.is_empty() {
            UserStatus::Invited
        } else {
            UserStatus::Enabled
        };

        json!({
            "_status": status as i32,
            "id": self.uuid,
            "name": self.name,
            "email": self.email,
            "emailVerified": !CONFIG.mail_enabled() || self.verified_at.is_some(),
            "premium": true,
            "premiumFromOrganization": false,
            "culture": "en-US",
            "twoFactorEnabled": twofactor_enabled,
            "key": self.akey,
            "privateKey": self.private_key,
            "securityStamp": self.security_stamp,
            "organizations": orgs_json,
            "providers": [],
            "providerOrganizations": [],
            "forcePasswordReset": false,
            "avatarColor": self.avatar_color,
            "usesKeyConnector": false,
            "creationDate": format_date(&self.created_at),
            "object": "profile",
        })
    }

    pub async fn save(&mut self, conn: &mut DbConn) -> EmptyResult {
        if !crate::util::is_valid_email(&self.email) {
            err!(format!("User email {} is not a valid email address", self.email))
        }

        self.updated_at = Utc::now().naive_utc();

        db_run! {conn:
            sqlite, mysql {
                match diesel::replace_into(users::table)
                    .values(UserDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(users::table)
                            .filter(users::uuid.eq(&self.uuid))
                            .set(UserDb::to_db(self))
                            .execute(conn)
                            .map_res("Error saving user")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving user")
            }
            postgresql {
                let value = UserDb::to_db(self);
                diesel::insert_into(users::table) // Insert or update
                    .values(&value)
                    .on_conflict(users::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving user")
            }
        }
    }

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
        for member in Membership::find_confirmed_by_user(&self.uuid, conn).await {
            if member.atype == MembershipType::Owner
                && Membership::count_confirmed_by_org_and_type(&member.org_uuid, MembershipType::Owner, conn).await <= 1
            {
                err!("Can't delete last owner")
            }
        }

        super::Send::delete_all_by_user(&self.uuid, conn).await?;
        EmergencyAccess::delete_all_by_user(&self.uuid, conn).await?;
        EmergencyAccess::delete_all_by_grantee_email(&self.email, conn).await?;
        Membership::delete_all_by_user(&self.uuid, conn).await?;
        Cipher::delete_all_by_user(&self.uuid, conn).await?;
        Favorite::delete_all_by_user(&self.uuid, conn).await?;
        Folder::delete_all_by_user(&self.uuid, conn).await?;
        Device::delete_all_by_user(&self.uuid, conn).await?;
        TwoFactor::delete_all_by_user(&self.uuid, conn).await?;
        TwoFactorIncomplete::delete_all_by_user(&self.uuid, conn).await?;
        Invitation::take(&self.email, conn).await; // Delete invitation if any

        db_run! {conn: {
            diesel::delete(users::table.filter(users::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting user")
        }}
    }

    pub async fn update_uuid_revision(uuid: &UserId, conn: &mut DbConn) {
        if let Err(e) = Self::_update_revision(uuid, &Utc::now().naive_utc(), conn).await {
            warn!("Failed to update revision for {uuid}: {e:#?}");
        }
    }

    pub async fn update_all_revisions(conn: &mut DbConn) -> EmptyResult {
        let updated_at = Utc::now().naive_utc();

        db_run! {conn: {
            retry(|| {
                diesel::update(users::table)
                    .set(users::updated_at.eq(updated_at))
                    .execute(conn)
            }, 10)
            .map_res("Error updating revision date for all users")
        }}
    }

    pub async fn update_revision(&mut self, conn: &mut DbConn) -> EmptyResult {
        self.updated_at = Utc::now().naive_utc();

        Self::_update_revision(&self.uuid, &self.updated_at, conn).await
    }

    async fn _update_revision(uuid: &UserId, date: &NaiveDateTime, conn: &mut DbConn) -> EmptyResult {
        db_run! {conn: {
            retry(|| {
                diesel::update(users::table.filter(users::uuid.eq(uuid)))
                    .set(users::updated_at.eq(date))
                    .execute(conn)
            }, 10)
            .map_res("Error updating user revision")
        }}
    }

    pub async fn find_by_mail(mail: &str, conn: &mut DbConn) -> Option<Self> {
        let lower_mail = mail.to_lowercase();
        db_run! {conn: {
            users::table
                .filter(users::email.eq(lower_mail))
                .first::<UserDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_by_uuid(uuid: &UserId, conn: &mut DbConn) -> Option<Self> {
        db_run! {conn: {
            users::table.filter(users::uuid.eq(uuid)).first::<UserDb>(conn).ok().from_db()
        }}
    }

    pub async fn find_by_device_id(device_uuid: &DeviceId, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            users::table
                .inner_join(devices::table.on(devices::user_uuid.eq(users::uuid)))
                .filter(devices::uuid.eq(device_uuid))
                .select(users::all_columns)
                .first::<UserDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn get_all(conn: &mut DbConn) -> Vec<(User, Option<SsoUser>)> {
        db_run! {conn: {
            users::table
                .left_join(sso_users::table)
                .select(<(UserDb, Option<SsoUserDb>)>::as_select())
                .load(conn)
                .expect("Error loading groups for user")
                .into_iter()
                .map(|(user, sso_user)| { (user.from_db(), sso_user.from_db()) })
                .collect()
        }}
    }

    pub async fn last_active(&self, conn: &mut DbConn) -> Option<NaiveDateTime> {
        match Device::find_latest_active_by_user(&self.uuid, conn).await {
            Some(device) => Some(device.updated_at),
            None => None,
        }
    }
}

impl Invitation {
    pub fn new(email: &str) -> Self {
        let email = email.to_lowercase();
        Self {
            email,
        }
    }

    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        if !crate::util::is_valid_email(&self.email) {
            err!(format!("Invitation email {} is not a valid email address", self.email))
        }

        db_run! {conn:
            sqlite, mysql {
                // Not checking for ForeignKey Constraints here
                // Table invitations does not have any ForeignKey Constraints.
                diesel::replace_into(invitations::table)
                    .values(InvitationDb::to_db(self))
                    .execute(conn)
                    .map_res("Error saving invitation")
            }
            postgresql {
                diesel::insert_into(invitations::table)
                    .values(InvitationDb::to_db(self))
                    .on_conflict(invitations::email)
                    .do_nothing()
                    .execute(conn)
                    .map_res("Error saving invitation")
            }
        }
    }

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
        db_run! {conn: {
            diesel::delete(invitations::table.filter(invitations::email.eq(self.email)))
                .execute(conn)
                .map_res("Error deleting invitation")
        }}
    }

    pub async fn find_by_mail(mail: &str, conn: &mut DbConn) -> Option<Self> {
        let lower_mail = mail.to_lowercase();
        db_run! {conn: {
            invitations::table
                .filter(invitations::email.eq(lower_mail))
                .first::<InvitationDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn take(mail: &str, conn: &mut DbConn) -> bool {
        match Self::find_by_mail(mail, conn).await {
            Some(invitation) => invitation.delete(conn).await.is_ok(),
            None => false,
        }
    }
}

#[derive(
    Clone,
    Debug,
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
    UuidFromParam,
)]
#[deref(forward)]
#[from(forward)]
pub struct UserId(String);

impl SsoUser {
    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                diesel::replace_into(sso_users::table)
                    .values(SsoUserDb::to_db(self))
                    .execute(conn)
                    .map_res("Error saving SSO user")
            }
            postgresql {
                let value = SsoUserDb::to_db(self);
                diesel::insert_into(sso_users::table)
                    .values(&value)
                    .execute(conn)
                    .map_res("Error saving SSO user")
            }
        }
    }

    pub async fn find_by_identifier(identifier: &str, conn: &DbConn) -> Option<(User, SsoUser)> {
        db_run! {conn: {
            users::table
                .inner_join(sso_users::table)
                .select(<(UserDb, SsoUserDb)>::as_select())
                .filter(sso_users::identifier.eq(identifier))
                .first::<(UserDb, SsoUserDb)>(conn)
                .ok()
                .map(|(user, sso_user)| { (user.from_db(), sso_user.from_db()) })
        }}
    }

    pub async fn find_by_mail(mail: &str, conn: &DbConn) -> Option<(User, Option<SsoUser>)> {
        let lower_mail = mail.to_lowercase();

        db_run! {conn: {
            users::table
                .left_join(sso_users::table)
                .select(<(UserDb, Option<SsoUserDb>)>::as_select())
                .filter(users::email.eq(lower_mail))
                .first::<(UserDb, Option<SsoUserDb>)>(conn)
                .ok()
                .map(|(user, sso_user)| { (user.from_db(), sso_user.from_db()) })
        }}
    }

    pub async fn delete(user_uuid: &UserId, conn: &mut DbConn) -> EmptyResult {
        db_run! {conn: {
            diesel::delete(sso_users::table.filter(sso_users::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error deleting sso user")
        }}
    }
}
