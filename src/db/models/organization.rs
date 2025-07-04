#![allow(unused_qualifications)]

use chrono::{NaiveDateTime, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::sql_query;
use diesel::sql_types::{Nullable, Text};
use num_traits::FromPrimitive;
use serde_json::Value;
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};

use super::{
    CipherId, Collection, CollectionGroup, CollectionId, CollectionUser, Group, GroupId, GroupUser, OrgPolicy,
    OrgPolicyType, TwoFactor, User, UserId,
};
use crate::CONFIG;
use macros::UuidFromParam;

db_object! {
    #[derive(Identifiable, Queryable, QueryableByName, Insertable, AsChangeset)]
    #[diesel(table_name = organizations)]
    #[diesel(treat_none_as_null = true)]
    #[diesel(primary_key(uuid))]
    pub struct Organization {
        pub uuid: OrganizationId,
        pub name: String,
        pub billing_email: String,
        pub private_key: Option<String>,
        pub public_key: Option<String>,
        pub external_id: Option<String>,
    }

    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = users_organizations)]
    #[diesel(treat_none_as_null = true)]
    #[diesel(primary_key(uuid))]
    pub struct Membership {
        pub uuid: MembershipId,
        pub user_uuid: UserId,
        pub org_uuid: OrganizationId,

        pub invited_by_email: Option<String>,

        pub access_all: bool,
        pub akey: String,
        pub status: i32,
        pub atype: i32,
        pub reset_password_key: Option<String>,
        pub external_id: Option<String>,
    }

    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = organization_api_key)]
    #[diesel(primary_key(uuid, org_uuid))]
    pub struct OrganizationApiKey {
        pub uuid: OrgApiKeyId,
        pub org_uuid: OrganizationId,
        pub atype: i32,
        pub api_key: String,
        pub revision_date: NaiveDateTime,
    }
}

// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/AdminConsole/Enums/OrganizationUserStatusType.cs
#[derive(Clone, PartialEq)]
pub enum MembershipStatus {
    Revoked = -1,
    Invited = 0,
    Accepted = 1,
    Confirmed = 2,
}

impl MembershipStatus {
    pub fn from_i32(status: i32) -> Option<Self> {
        match status {
            0 => Some(Self::Invited),
            1 => Some(Self::Accepted),
            2 => Some(Self::Confirmed),
            // NOTE: we don't care about revoked members where this is used
            // if this ever changes also adapt the OrgHeaders check.
            _ => None,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, num_derive::FromPrimitive)]
pub enum MembershipType {
    Owner = 0,
    Admin = 1,
    User = 2,
    Manager = 3,
}

impl MembershipType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "0" | "Owner" => Some(MembershipType::Owner),
            "1" | "Admin" => Some(MembershipType::Admin),
            "2" | "User" => Some(MembershipType::User),
            "3" | "Manager" => Some(MembershipType::Manager),
            // HACK: We convert the custom role to a manager role
            "4" | "Custom" => Some(MembershipType::Manager),
            _ => None,
        }
    }
}

impl Ord for MembershipType {
    fn cmp(&self, other: &MembershipType) -> Ordering {
        // For easy comparison, map each variant to an access level (where 0 is lowest).
        const ACCESS_LEVEL: [i32; 4] = [
            3, // Owner
            2, // Admin
            0, // User
            1, // Manager && Custom
        ];
        ACCESS_LEVEL[*self as usize].cmp(&ACCESS_LEVEL[*other as usize])
    }
}

impl PartialOrd for MembershipType {
    fn partial_cmp(&self, other: &MembershipType) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq<i32> for MembershipType {
    fn eq(&self, other: &i32) -> bool {
        *other == *self as i32
    }
}

impl PartialOrd<i32> for MembershipType {
    fn partial_cmp(&self, other: &i32) -> Option<Ordering> {
        if let Some(other) = Self::from_i32(*other) {
            return Some(self.cmp(&other));
        }
        None
    }

    fn gt(&self, other: &i32) -> bool {
        matches!(self.partial_cmp(other), Some(Ordering::Greater))
    }

    fn ge(&self, other: &i32) -> bool {
        matches!(self.partial_cmp(other), Some(Ordering::Greater | Ordering::Equal))
    }
}

impl PartialEq<MembershipType> for i32 {
    fn eq(&self, other: &MembershipType) -> bool {
        *self == *other as i32
    }
}

impl PartialOrd<MembershipType> for i32 {
    fn partial_cmp(&self, other: &MembershipType) -> Option<Ordering> {
        if let Some(self_type) = MembershipType::from_i32(*self) {
            return Some(self_type.cmp(other));
        }
        None
    }

    fn lt(&self, other: &MembershipType) -> bool {
        matches!(self.partial_cmp(other), Some(Ordering::Less) | None)
    }

    fn le(&self, other: &MembershipType) -> bool {
        matches!(self.partial_cmp(other), Some(Ordering::Less | Ordering::Equal) | None)
    }
}

/// Local methods
impl Organization {
    pub fn new(name: String, billing_email: String, private_key: Option<String>, public_key: Option<String>) -> Self {
        let billing_email = billing_email.to_lowercase();
        Self {
            uuid: OrganizationId(crate::util::get_uuid()),
            name,
            billing_email,
            private_key,
            public_key,
            external_id: None,
        }
    }
    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/AdminConsole/Models/Response/Organizations/OrganizationResponseModel.cs
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "name": self.name,
            "seats": null,
            "maxCollections": null,
            "maxStorageGb": i16::MAX, // The value doesn't matter, we don't check server-side
            "use2fa": true,
            "useCustomPermissions": true,
            "useDirectory": false, // Is supported, but this value isn't checked anywhere (yet)
            "useEvents": CONFIG.org_events_enabled(),
            "useGroups": CONFIG.org_groups_enabled(),
            "useTotp": true,
            "usePolicies": true,
            "useScim": false, // Not supported (Not AGPLv3 Licensed)
            "useSso": false, // Not supported
            "useKeyConnector": false, // Not supported
            "usePasswordManager": true,
            "useSecretsManager": false, // Not supported (Not AGPLv3 Licensed)
            "selfHost": true,
            "useApi": true,
            "hasPublicAndPrivateKeys": self.private_key.is_some() && self.public_key.is_some(),
            "useResetPassword": CONFIG.mail_enabled(),
            "allowAdminAccessToAllCollectionItems": true,
            "limitCollectionCreation": true,
            "limitCollectionDeletion": true,

            "businessName": self.name,
            "businessAddress1": null,
            "businessAddress2": null,
            "businessAddress3": null,
            "businessCountry": null,
            "businessTaxNumber": null,

            "maxAutoscaleSeats": null,
            "maxAutoscaleSmSeats": null,
            "maxAutoscaleSmServiceAccounts": null,

            "secretsManagerPlan": null,
            "smSeats": null,
            "smServiceAccounts": null,

            "billingEmail": self.billing_email,
            "planType": 6, // Custom plan
            "usersGetPremium": true,
            "object": "organization",

            // Custom field used for SSO org mapping
            "externalId": self.external_id,
        })
    }
}

// Used to either subtract or add to the current status
// The number 128 should be fine, it is well within the range of an i32
// The same goes for the database where we only use INTEGER (the same as an i32)
// It should also provide enough room for 100+ types, which i doubt will ever happen.
const ACTIVATE_REVOKE_DIFF: i32 = 128;

impl Membership {
    pub fn new(user_uuid: UserId, org_uuid: OrganizationId, invited_by_email: Option<String>) -> Self {
        Self {
            uuid: MembershipId(crate::util::get_uuid()),

            user_uuid,
            org_uuid,
            invited_by_email,

            access_all: false,
            akey: String::new(),
            status: MembershipStatus::Accepted as i32,
            atype: MembershipType::User as i32,
            reset_password_key: None,
            external_id: None,
        }
    }

    pub fn is_revoked(&self) -> bool {
        self.status < MembershipStatus::Invited as i32
    }

    pub fn restore(&mut self) -> bool {
        if self.is_revoked() {
            self.status += ACTIVATE_REVOKE_DIFF;
            return true;
        }
        false
    }

    pub fn revoke(&mut self) -> bool {
        if !self.is_revoked() {
            self.status -= ACTIVATE_REVOKE_DIFF;
            return true;
        }
        false
    }

    /// Return the status of the user in an unrevoked state
    pub fn get_unrevoked_status(&self) -> i32 {
        if self.is_revoked() {
            return self.status + ACTIVATE_REVOKE_DIFF;
        }
        self.status
    }

    pub fn set_external_id(&mut self, external_id: Option<String>) -> bool {
        //Check if external id is empty. We don't want to have
        //empty strings in the database
        if self.external_id != external_id {
            self.external_id = match external_id {
                Some(external_id) if !external_id.is_empty() => Some(external_id),
                _ => None,
            };
            return true;
        }
        false
    }

    /// HACK: Convert the manager type to a custom type
    /// It will be converted back on other locations
    pub fn type_manager_as_custom(&self) -> i32 {
        match self.atype {
            3 => 4,
            _ => self.atype,
        }
    }
}

impl OrganizationApiKey {
    pub fn new(org_uuid: OrganizationId, api_key: String) -> Self {
        Self {
            uuid: OrgApiKeyId(crate::util::get_uuid()),

            org_uuid,
            atype: 0, // Type 0 is the default and only type we support currently
            api_key,
            revision_date: Utc::now().naive_utc(),
        }
    }

    pub fn check_valid_api_key(&self, api_key: &str) -> bool {
        crate::crypto::ct_eq(&self.api_key, api_key)
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

#[derive(Debug, QueryableByName)]
struct OrgGroupSearch {
    #[diesel(sql_type = Text)]
    ogs_name_id: String,

    #[diesel(sql_type = Nullable<Text>)]
    ogs_group: Option<String>,

    #[diesel(sql_type = Nullable<Text>)]
    ogs_group_uuid: Option<GroupId>,
}

/// Database methods
impl Organization {
    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        if !crate::util::is_valid_email(&self.billing_email) {
            err!(format!("BillingEmail {} is not a valid email address", self.billing_email))
        }

        for member in Membership::find_by_org(&self.uuid, conn).await.iter() {
            User::update_uuid_revision(&member.user_uuid, conn).await;
        }

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(organizations::table)
                    .values(OrganizationDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(organizations::table)
                            .filter(organizations::uuid.eq(&self.uuid))
                            .set(OrganizationDb::to_db(self))
                            .execute(conn)
                            .map_res("Error saving organization")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving organization")

            }
            postgresql {
                let value = OrganizationDb::to_db(self);
                diesel::insert_into(organizations::table)
                    .values(&value)
                    .on_conflict(organizations::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving organization")
            }
        }
    }

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
        use super::{Cipher, Collection};

        Cipher::delete_all_by_organization(&self.uuid, conn).await?;
        Collection::delete_all_by_organization(&self.uuid, conn).await?;
        Membership::delete_all_by_organization(&self.uuid, conn).await?;
        OrgPolicy::delete_all_by_organization(&self.uuid, conn).await?;
        Group::delete_all_by_organization(&self.uuid, conn).await?;
        OrganizationApiKey::delete_all_by_organization(&self.uuid, conn).await?;

        db_run! { conn: {
            diesel::delete(organizations::table.filter(organizations::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error saving organization")
        }}
    }

    pub async fn find_by_uuid(uuid: &OrganizationId, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            organizations::table
                .filter(organizations::uuid.eq(uuid))
                .first::<OrganizationDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_by_uuids_or_names(
        uuids: &Vec<OrganizationId>,
        names: &Vec<String>,
        conn: &mut DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            organizations::table
                .filter(
                    organizations::uuid.eq_any(uuids).or(organizations::name.eq_any(names))
                )
                .load::<OrganizationDb>(conn)
                .expect("Error loading organizations").from_db()
        }}
    }

    pub async fn find_by_name(name: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            organizations::table
                .filter(organizations::name.eq(name))
                .first::<OrganizationDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn get_all(conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            organizations::table.load::<OrganizationDb>(conn).expect("Error loading organizations").from_db()
        }}
    }

    pub async fn find_main_org_user_email(user_email: &str, conn: &mut DbConn) -> Option<Organization> {
        let lower_mail = user_email.to_lowercase();

        db_run! { conn: {
            organizations::table
                .inner_join(users_organizations::table.on(users_organizations::org_uuid.eq(organizations::uuid)))
                .inner_join(users::table.on(users::uuid.eq(users_organizations::user_uuid)))
                .filter(users::email.eq(lower_mail))
                .filter(users_organizations::status.ne(MembershipStatus::Revoked as i32))
                .order(users_organizations::atype.asc())
                .select(organizations::all_columns)
                .first::<OrganizationDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_org_user_email(user_email: &str, conn: &mut DbConn) -> Vec<Organization> {
        let lower_mail = user_email.to_lowercase();

        db_run! { conn: {
            organizations::table
                .inner_join(users_organizations::table.on(users_organizations::org_uuid.eq(organizations::uuid)))
                .inner_join(users::table.on(users::uuid.eq(users_organizations::user_uuid)))
                .filter(users::email.eq(lower_mail))
                .filter(users_organizations::status.ne(MembershipStatus::Revoked as i32))
                .order(users_organizations::atype.asc())
                .select(organizations::all_columns)
                .load::<OrganizationDb>(conn)
                .expect("Error loading user orgs")
                .from_db()
        }}
    }

    // Issues with different databases:
    //  - Postgres placeholder is $n instead of ?
    //  - Mysql VALUES expect ROW(?, ?) instead of (?, ?) -> force us to use SELECT/UNION
    //  - Mariadb binding of Nullable appears to fail -> force us to bind ""
    fn prepared_query(count: usize, is_postgres: bool) -> String {
        let (escaped_group_table, values) = if is_postgres {
            ("groups", (0..count).map(|i| format!("SELECT ${}, ${}", 1 + 2 * i, 2 + 2 * i)).collect())
        } else {
            ("`groups`", std::iter::repeat_n("SELECT ?, ?".to_string(), count).collect::<Vec<String>>())
        };

        let query = format!(
            r#"
            WITH raw(ogs_name_id, ogs_group) AS ( {} ),
            ident(ogs_name_id, ogs_group) AS ( SELECT ogs_name_id, CASE when LENGTH(ogs_group) = 0 THEN null ELSE ogs_group END FROM raw)
            SELECT ident.ogs_name_id, ident.ogs_group, organizations.*, groups.uuid AS ogs_group_uuid
                FROM ident
                LEFT JOIN organizations ON TRUE
                LEFT JOIN {} ON groups.organizations_uuid = organizations.uuid  AND ( groups.name = ident.ogs_group OR groups.external_id = ident.ogs_name_id )
                WHERE ( organizations.name = ident.ogs_name_id AND groups.name = ident.ogs_group)
                    OR ((organizations.name = ident.ogs_name_id OR organizations.external_id = ident.ogs_name_id) AND groups.uuid is null AND ident.ogs_group is null )
                    OR (groups.external_id = ident.ogs_name_id AND ident.ogs_group is null);"#,
            values.join(" UNION ALL "),
            escaped_group_table
        );

        debug!("find_mapped_orgs_and_groups query: {query:?}");

        query
    }

    pub async fn find_mapped_orgs_and_groups(
        params: Vec<(String, Option<String>)>,
        conn: &DbConn,
    ) -> Vec<(String, Option<String>, Self, Option<GroupId>)> {
        debug!("find_mapped_orgs_and_groups({params:?})");
        if !params.is_empty() {
            db_run! { conn:
                sqlite, mysql {
                    let mut query = sql_query(Self::prepared_query(params.len(), false)).into_boxed();
                    for (id, group) in params {
                        query = query.bind::<Text, _>(id).bind::<Text, _>(group.unwrap_or(String::new()));
                    }
                    query
                        .load::<(OrgGroupSearch, OrganizationDb)>(conn)
                        .expect("Error loading orgs and groups")
                        .into_iter()
                        .map(|(ogs, org)| (ogs.ogs_name_id, ogs.ogs_group, org.from_db(), ogs.ogs_group_uuid) )
                        .collect()
                }
                postgresql {
                    let mut query = sql_query(Self::prepared_query(params.len(), true)).into_boxed();
                    for (id, group) in params {
                        query = query.bind::<Text, _>(id).bind::<Nullable<Text>, _>(group);
                    }
                    query
                        .load::<(OrgGroupSearch, OrganizationDb)>(conn)
                        .expect("Error loading orgs and groups")
                        .into_iter()
                        .map(|(ogs, org)| (ogs.ogs_name_id, ogs.ogs_group, org.from_db(), ogs.ogs_group_uuid) )
                        .collect()
                }
            }
        } else {
            Vec::new()
        }
    }
}

impl Membership {
    pub async fn to_json(&self, conn: &mut DbConn) -> Value {
        let org = Organization::find_by_uuid(&self.org_uuid, conn).await.unwrap();

        // HACK: Convert the manager type to a custom type
        // It will be converted back on other locations
        let membership_type = self.type_manager_as_custom();

        let permissions = json!({
                // TODO: Add full support for Custom User Roles
                // See: https://bitwarden.com/help/article/user-types-access-control/#custom-role
                // Currently we use the custom role as a manager role and link the 3 Collection roles to mimic the access_all permission
                "accessEventLogs": false,
                "accessImportExport": false,
                "accessReports": false,
                // If the following 3 Collection roles are set to true a custom user has access all permission
                "createNewCollections": membership_type == 4 && self.access_all,
                "editAnyCollection": membership_type == 4 && self.access_all,
                "deleteAnyCollection": membership_type == 4 && self.access_all,
                "manageGroups": false,
                "managePolicies": false,
                "manageSso": false, // Not supported
                "manageUsers": false,
                "manageResetPassword": false,
                "manageScim": false // Not supported (Not AGPLv3 Licensed)
        });

        // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/AdminConsole/Models/Response/ProfileOrganizationResponseModel.cs
        json!({
            "id": self.org_uuid,
            "identifier": null, // Not supported
            "name": org.name,
            "seats": null,
            "maxCollections": null,
            "usersGetPremium": true,
            "use2fa": true,
            "useDirectory": false, // Is supported, but this value isn't checked anywhere (yet)
            "useEvents": CONFIG.org_events_enabled(),
            "useGroups": CONFIG.org_groups_enabled(),
            "useTotp": true,
            "useScim": false, // Not supported (Not AGPLv3 Licensed)
            "usePolicies": true,
            "useApi": true,
            "selfHost": true,
            "hasPublicAndPrivateKeys": org.private_key.is_some() && org.public_key.is_some(),
            "resetPasswordEnrolled": self.reset_password_key.is_some(),
            "useResetPassword": CONFIG.mail_enabled(),
            "ssoBound": false, // Not supported
            "useSso": false, // Not supported
            "useKeyConnector": false,
            "useSecretsManager": false, // Not supported (Not AGPLv3 Licensed)
            "usePasswordManager": true,
            "useCustomPermissions": true,
            "useActivateAutofillPolicy": false,
            "useAdminSponsoredFamilies": false,
            "useRiskInsights": false, // Not supported (Not AGPLv3 Licensed)

            "organizationUserId": self.uuid,
            "providerId": null,
            "providerName": null,
            "providerType": null,
            "familySponsorshipFriendlyName": null,
            "familySponsorshipAvailable": false,
            "productTierType": 3, // Enterprise tier
            "keyConnectorEnabled": false,
            "keyConnectorUrl": null,
            "familySponsorshipLastSyncDate": null,
            "familySponsorshipValidUntil": null,
            "familySponsorshipToDelete": null,
            "accessSecretsManager": false,
            "limitCollectionCreation": self.atype < MembershipType::Manager, // If less then a manager return true, to limit collection creations
            "limitCollectionDeletion": true,
            "limitItemDeletion": false,
            "allowAdminAccessToAllCollectionItems": true,
            "userIsManagedByOrganization": false, // Means not managed via the Members UI, like SSO
            "userIsClaimedByOrganization": false, // The new key instead of the obsolete userIsManagedByOrganization

            "permissions": permissions,

            "maxStorageGb": i16::MAX, // The value doesn't matter, we don't check server-side

            // These are per user
            "userId": self.user_uuid,
            "key": self.akey,
            "status": self.status,
            "type": membership_type,
            "enabled": true,

            "object": "profileOrganization",
        })
    }

    pub async fn to_json_user_details(
        &self,
        include_collections: bool,
        include_groups: bool,
        conn: &mut DbConn,
    ) -> Value {
        let user = User::find_by_uuid(&self.user_uuid, conn).await.unwrap();

        // Because BitWarden want the status to be -1 for revoked users we need to catch that here.
        // We subtract/add a number so we can restore/activate the user to it's previous state again.
        let status = if self.status < MembershipStatus::Revoked as i32 {
            MembershipStatus::Revoked as i32
        } else {
            self.status
        };

        let twofactor_enabled = !TwoFactor::find_by_user(&user.uuid, conn).await.is_empty();

        let groups: Vec<GroupId> = if include_groups && CONFIG.org_groups_enabled() {
            GroupUser::find_by_member(&self.uuid, conn).await.iter().map(|gu| gu.groups_uuid.clone()).collect()
        } else {
            // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
            // so just act as if there are no groups.
            Vec::with_capacity(0)
        };

        // Check if a user is in a group which has access to all collections
        // If that is the case, we should not return individual collections!
        let full_access_group =
            CONFIG.org_groups_enabled() && Group::is_in_full_access_group(&self.user_uuid, &self.org_uuid, conn).await;

        // If collections are to be included, only include them if the user does not have full access via a group or defined to the user it self
        let collections: Vec<Value> = if include_collections && !(full_access_group || self.access_all) {
            // Get all collections for the user here already to prevent more queries
            let cu: HashMap<CollectionId, CollectionUser> =
                CollectionUser::find_by_organization_and_user_uuid(&self.org_uuid, &self.user_uuid, conn)
                    .await
                    .into_iter()
                    .map(|cu| (cu.collection_uuid.clone(), cu))
                    .collect();

            // Get all collection groups for this user to prevent there inclusion
            let cg: HashSet<CollectionId> = CollectionGroup::find_by_user(&self.user_uuid, conn)
                .await
                .into_iter()
                .map(|cg| cg.collections_uuid)
                .collect();

            Collection::find_by_organization_and_user_uuid(&self.org_uuid, &self.user_uuid, conn)
                .await
                .into_iter()
                .filter_map(|c| {
                    let (read_only, hide_passwords, manage) = if self.has_full_access() {
                        (false, false, self.atype >= MembershipType::Manager)
                    } else if let Some(cu) = cu.get(&c.uuid) {
                        (
                            cu.read_only,
                            cu.hide_passwords,
                            cu.manage || (self.atype == MembershipType::Manager && !cu.read_only && !cu.hide_passwords),
                        )
                    // If previous checks failed it might be that this user has access via a group, but we should not return those elements here
                    // Those are returned via a special group endpoint
                    } else if cg.contains(&c.uuid) {
                        return None;
                    } else {
                        (true, true, false)
                    };

                    Some(json!({
                        "id": c.uuid,
                        "readOnly": read_only,
                        "hidePasswords": hide_passwords,
                        "manage": manage,
                    }))
                })
                .collect()
        } else {
            Vec::with_capacity(0)
        };

        // HACK: Convert the manager type to a custom type
        // It will be converted back on other locations
        let membership_type = self.type_manager_as_custom();

        // HACK: Only return permissions if the user is of type custom and has access_all
        // Else Bitwarden will assume the defaults of all false
        let permissions = if membership_type == 4 && self.access_all {
            json!({
                // TODO: Add full support for Custom User Roles
                // See: https://bitwarden.com/help/article/user-types-access-control/#custom-role
                // Currently we use the custom role as a manager role and link the 3 Collection roles to mimic the access_all permission
                "accessEventLogs": false,
                "accessImportExport": false,
                "accessReports": false,
                // If the following 3 Collection roles are set to true a custom user has access all permission
                "createNewCollections": true,
                "editAnyCollection": true,
                "deleteAnyCollection": true,
                "manageGroups": false,
                "managePolicies": false,
                "manageSso": false, // Not supported
                "manageUsers": false,
                "manageResetPassword": false,
                "manageScim": false // Not supported (Not AGPLv3 Licensed)
            })
        } else {
            json!(null)
        };

        json!({
            "id": self.uuid,
            "userId": self.user_uuid,
            "name": if self.get_unrevoked_status() >= MembershipStatus::Accepted as i32 { Some(user.name) } else { None },
            "email": user.email,
            "externalId": self.external_id,
            "avatarColor": user.avatar_color,
            "groups": groups,
            "collections": collections,

            "status": status,
            "type": membership_type,
            "accessAll": self.access_all,
            "twoFactorEnabled": twofactor_enabled,
            "resetPasswordEnrolled": self.reset_password_key.is_some(),
            "hasMasterPassword": !user.password_hash.is_empty(),

            "permissions": permissions,

            "ssoBound": false, // Not supported
            "managedByOrganization": false, // This key is obsolete replaced by claimedByOrganization
            "claimedByOrganization": false, // Means not managed via the Members UI, like SSO
            "usesKeyConnector": false, // Not supported
            "accessSecretsManager": false, // Not supported (Not AGPLv3 Licensed)

            "object": "organizationUserUserDetails",
        })
    }

    pub fn to_json_user_access_restrictions(&self, col_user: &CollectionUser) -> Value {
        json!({
            "id": self.uuid,
            "readOnly": col_user.read_only,
            "hidePasswords": col_user.hide_passwords,
            "manage": col_user.manage,
        })
    }

    pub async fn to_json_details(&self, conn: &mut DbConn) -> Value {
        let coll_uuids = if self.access_all {
            vec![] // If we have complete access, no need to fill the array
        } else {
            let collections =
                CollectionUser::find_by_organization_and_user_uuid(&self.org_uuid, &self.user_uuid, conn).await;
            collections
                .iter()
                .map(|cu| {
                    json!({
                        "id": cu.collection_uuid,
                        "readOnly": cu.read_only,
                        "hidePasswords": cu.hide_passwords,
                        "manage": cu.manage,
                    })
                })
                .collect()
        };

        // Because BitWarden want the status to be -1 for revoked users we need to catch that here.
        // We subtract/add a number so we can restore/activate the user to it's previous state again.
        let status = if self.status < MembershipStatus::Revoked as i32 {
            MembershipStatus::Revoked as i32
        } else {
            self.status
        };

        json!({
            "id": self.uuid,
            "userId": self.user_uuid,

            "status": status,
            "type": self.atype,
            "accessAll": self.access_all,
            "collections": coll_uuids,

            "object": "organizationUserDetails",
        })
    }

    pub async fn to_json_mini_details(&self, conn: &mut DbConn) -> Value {
        let user = User::find_by_uuid(&self.user_uuid, conn).await.unwrap();

        // Because Bitwarden wants the status to be -1 for revoked users we need to catch that here.
        // We subtract/add a number so we can restore/activate the user to it's previous state again.
        let status = if self.status < MembershipStatus::Revoked as i32 {
            MembershipStatus::Revoked as i32
        } else {
            self.status
        };

        json!({
            "id": self.uuid,
            "userId": self.user_uuid,
            "type": self.type_manager_as_custom(), // HACK: Convert the manager type to a custom type
            "status": status,
            "name": user.name,
            "email": user.email,
            "object": "organizationUserUserMiniDetails",
        })
    }

    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn).await;

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(users_organizations::table)
                    .values(MembershipDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(users_organizations::table)
                            .filter(users_organizations::uuid.eq(&self.uuid))
                            .set(MembershipDb::to_db(self))
                            .execute(conn)
                            .map_res("Error adding user to organization")
                    },
                    Err(e) => Err(e.into()),
                }.map_res("Error adding user to organization")
            }
            postgresql {
                let value = MembershipDb::to_db(self);
                diesel::insert_into(users_organizations::table)
                    .values(&value)
                    .on_conflict(users_organizations::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error adding user to organization")
            }
        }
    }

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn).await;

        CollectionUser::delete_all_by_user_and_org(&self.user_uuid, &self.org_uuid, conn).await?;
        GroupUser::delete_all_by_member(&self.uuid, conn).await?;

        db_run! { conn: {
            diesel::delete(users_organizations::table.filter(users_organizations::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error removing user from organization")
        }}
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &mut DbConn) -> EmptyResult {
        for member in Self::find_by_org(org_uuid, conn).await {
            member.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &mut DbConn) -> EmptyResult {
        for member in Self::find_any_state_by_user(user_uuid, conn).await {
            member.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn find_by_email_and_org(
        email: &str,
        org_uuid: &OrganizationId,
        conn: &mut DbConn,
    ) -> Option<Membership> {
        if let Some(user) = User::find_by_mail(email, conn).await {
            if let Some(member) = Membership::find_by_user_and_org(&user.uuid, org_uuid, conn).await {
                return Some(member);
            }
        }

        None
    }

    pub fn has_status(&self, status: MembershipStatus) -> bool {
        self.status == status as i32
    }

    pub fn has_type(&self, user_type: MembershipType) -> bool {
        self.atype == user_type as i32
    }

    pub fn has_full_access(&self) -> bool {
        (self.access_all || self.atype >= MembershipType::Admin) && self.has_status(MembershipStatus::Confirmed)
    }

    pub async fn find_by_uuid(uuid: &MembershipId, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::uuid.eq(uuid))
                .first::<MembershipDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_by_uuid_and_org(
        uuid: &MembershipId,
        org_uuid: &OrganizationId,
        conn: &mut DbConn,
    ) -> Option<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::uuid.eq(uuid))
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .first::<MembershipDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_confirmed_by_user(user_uuid: &UserId, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .load::<MembershipDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    pub async fn find_invited_by_user(user_uuid: &UserId, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Invited as i32))
                .load::<MembershipDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    // Should be used only when email are disabled.
    // In Organizations::send_invite status is set to Accepted only if the user has a password.
    pub async fn accept_user_invitations(user_uuid: &UserId, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::update(users_organizations::table)
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Invited as i32))
                .set(users_organizations::status.eq(MembershipStatus::Accepted as i32))
                .execute(conn)
                .map_res("Error confirming invitations")
        }}
    }

    pub async fn find_any_state_by_user(user_uuid: &UserId, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .load::<MembershipDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    pub async fn count_accepted_and_confirmed_by_user(user_uuid: &UserId, conn: &mut DbConn) -> i64 {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Accepted as i32).or(users_organizations::status.eq(MembershipStatus::Confirmed as i32)))
                .count()
                .first::<i64>(conn)
                .unwrap_or(0)
        }}
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .load::<MembershipDb>(conn)
                .expect("Error loading user organizations").from_db()
        }}
    }

    pub async fn find_confirmed_by_org(org_uuid: &OrganizationId, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .load::<MembershipDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    // Get all users which are either owner or admin, or a manager which can manage/access all
    pub async fn find_confirmed_and_manage_all_by_org(org_uuid: &OrganizationId, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .filter(
                    users_organizations::atype.eq_any(vec![MembershipType::Owner as i32, MembershipType::Admin as i32])
                    .or(users_organizations::atype.eq(MembershipType::Manager as i32).and(users_organizations::access_all.eq(true)))
                )
                .load::<MembershipDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    pub async fn count_by_org(org_uuid: &OrganizationId, conn: &mut DbConn) -> i64 {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
        }}
    }

    pub async fn find_by_org_and_type(
        org_uuid: &OrganizationId,
        atype: MembershipType,
        conn: &mut DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::atype.eq(atype as i32))
                .load::<MembershipDb>(conn)
                .expect("Error loading user organizations").from_db()
        }}
    }

    pub async fn count_confirmed_by_org_and_type(
        org_uuid: &OrganizationId,
        atype: MembershipType,
        conn: &mut DbConn,
    ) -> i64 {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::atype.eq(atype as i32))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .count()
                .first::<i64>(conn)
                .unwrap_or(0)
        }}
    }

    pub async fn find_by_user_and_org(
        user_uuid: &UserId,
        org_uuid: &OrganizationId,
        conn: &mut DbConn,
    ) -> Option<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .first::<MembershipDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_confirmed_by_user_and_org(
        user_uuid: &UserId,
        org_uuid: &OrganizationId,
        conn: &mut DbConn,
    ) -> Option<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(
                    users_organizations::status.eq(MembershipStatus::Confirmed as i32)
                )
                .first::<MembershipDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .load::<MembershipDb>(conn)
                .expect("Error loading user organizations").from_db()
        }}
    }

    pub async fn get_orgs_by_user(user_uuid: &UserId, conn: &mut DbConn) -> Vec<OrganizationId> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .select(users_organizations::org_uuid)
                .load::<OrganizationId>(conn)
                .unwrap_or_default()
        }}
    }

    pub async fn find_by_user_and_policy(
        user_uuid: &UserId,
        policy_type: OrgPolicyType,
        conn: &mut DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .inner_join(
                    org_policies::table.on(
                        org_policies::org_uuid.eq(users_organizations::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid))
                            .and(org_policies::atype.eq(policy_type as i32))
                            .and(org_policies::enabled.eq(true)))
                )
                .filter(
                    users_organizations::status.eq(MembershipStatus::Confirmed as i32)
                )
                .select(users_organizations::all_columns)
                .load::<MembershipDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    pub async fn find_by_cipher_and_org(
        cipher_uuid: &CipherId,
        org_uuid: &OrganizationId,
        conn: &mut DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
            .filter(users_organizations::org_uuid.eq(org_uuid))
            .left_join(users_collections::table.on(
                users_collections::user_uuid.eq(users_organizations::user_uuid)
            ))
            .left_join(ciphers_collections::table.on(
                ciphers_collections::collection_uuid.eq(users_collections::collection_uuid).and(
                    ciphers_collections::cipher_uuid.eq(&cipher_uuid)
                )
            ))
            .filter(
                users_organizations::access_all.eq(true).or( // AccessAll..
                    ciphers_collections::cipher_uuid.eq(&cipher_uuid) // ..or access to collection with cipher
                )
            )
            .select(users_organizations::all_columns)
            .distinct()
            .load::<MembershipDb>(conn).expect("Error loading user organizations").from_db()
        }}
    }

    pub async fn find_by_cipher_and_org_with_group(
        cipher_uuid: &CipherId,
        org_uuid: &OrganizationId,
        conn: &mut DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
            .filter(users_organizations::org_uuid.eq(org_uuid))
            .inner_join(groups_users::table.on(
                groups_users::users_organizations_uuid.eq(users_organizations::uuid)
            ))
            .left_join(collections_groups::table.on(
                collections_groups::groups_uuid.eq(groups_users::groups_uuid)
            ))
            .left_join(groups::table.on(groups::uuid.eq(groups_users::groups_uuid)))
            .left_join(ciphers_collections::table.on(
                    ciphers_collections::collection_uuid.eq(collections_groups::collections_uuid).and(ciphers_collections::cipher_uuid.eq(&cipher_uuid))

                ))
            .filter(
                    groups::access_all.eq(true).or( // AccessAll via groups
                        ciphers_collections::cipher_uuid.eq(&cipher_uuid) // ..or access to collection via group
                    )
                )
                .select(users_organizations::all_columns)
                .distinct()
            .load::<MembershipDb>(conn).expect("Error loading user organizations with groups").from_db()
        }}
    }

    pub async fn user_has_ge_admin_access_to_cipher(
        user_uuid: &UserId,
        cipher_uuid: &CipherId,
        conn: &mut DbConn,
    ) -> bool {
        db_run! { conn: {
            users_organizations::table
            .inner_join(ciphers::table.on(ciphers::uuid.eq(cipher_uuid).and(ciphers::organization_uuid.eq(users_organizations::org_uuid.nullable()))))
            .filter(users_organizations::user_uuid.eq(user_uuid))
            .filter(users_organizations::atype.eq_any(vec![MembershipType::Owner as i32, MembershipType::Admin as i32]))
            .count()
            .first::<i64>(conn)
            .ok().unwrap_or(0) != 0
        }}
    }

    pub async fn find_by_collection_and_org(
        collection_uuid: &CollectionId,
        org_uuid: &OrganizationId,
        conn: &mut DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
            .filter(users_organizations::org_uuid.eq(org_uuid))
            .left_join(users_collections::table.on(
                users_collections::user_uuid.eq(users_organizations::user_uuid)
            ))
            .filter(
                users_organizations::access_all.eq(true).or( // AccessAll..
                    users_collections::collection_uuid.eq(&collection_uuid) // ..or access to collection with cipher
                )
            )
            .select(users_organizations::all_columns)
            .load::<MembershipDb>(conn).expect("Error loading user organizations").from_db()
        }}
    }

    pub async fn find_by_external_id_and_org(
        ext_id: &str,
        org_uuid: &OrganizationId,
        conn: &mut DbConn,
    ) -> Option<Self> {
        db_run! {conn: {
            users_organizations::table
            .filter(
                users_organizations::external_id.eq(ext_id)
                .and(users_organizations::org_uuid.eq(org_uuid))
            )
            .first::<MembershipDb>(conn).ok().from_db()
        }}
    }

    pub async fn find_main_user_org(user_uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.ne(MembershipStatus::Revoked as i32))
                .order(users_organizations::atype.asc())
                .first::<MembershipDb>(conn)
                .ok().from_db()
        }}
    }
}

impl OrganizationApiKey {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(organization_api_key::table)
                    .values(OrganizationApiKeyDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(organization_api_key::table)
                            .filter(organization_api_key::uuid.eq(&self.uuid))
                            .set(OrganizationApiKeyDb::to_db(self))
                            .execute(conn)
                            .map_res("Error saving organization")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving organization")

            }
            postgresql {
                let value = OrganizationApiKeyDb::to_db(self);
                diesel::insert_into(organization_api_key::table)
                    .values(&value)
                    .on_conflict((organization_api_key::uuid, organization_api_key::org_uuid))
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving organization")
            }
        }
    }

    pub async fn find_by_org_uuid(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            organization_api_key::table
                .filter(organization_api_key::org_uuid.eq(org_uuid))
                .first::<OrganizationApiKeyDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(organization_api_key::table.filter(organization_api_key::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error removing organization api key from organization")
        }}
    }
}

#[derive(
    Clone,
    Debug,
    AsRef,
    Deref,
    DieselNewType,
    Display,
    From,
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    UuidFromParam,
)]
#[deref(forward)]
#[from(forward)]
pub struct OrganizationId(String);

#[derive(
    Clone,
    Debug,
    Deref,
    DieselNewType,
    Display,
    From,
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    UuidFromParam,
)]
pub struct MembershipId(String);

#[derive(Clone, Debug, DieselNewType, Display, FromForm, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgApiKeyId(String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn partial_cmp_MembershipType() {
        assert!(MembershipType::Owner > MembershipType::Admin);
        assert!(MembershipType::Admin > MembershipType::Manager);
        assert!(MembershipType::Manager > MembershipType::User);
        assert!(MembershipType::Manager == MembershipType::from_str("4").unwrap());
    }
}
