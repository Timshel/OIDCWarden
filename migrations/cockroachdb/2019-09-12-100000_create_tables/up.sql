CREATE TABLE users (
  uuid                VARCHAR(40) NOT NULL PRIMARY KEY,
  created_at          TIMESTAMP NOT NULL,
  updated_at          TIMESTAMP NOT NULL,
  email               TEXT NOT NULL UNIQUE,
  name                TEXT NOT NULL,
  password_hash       BYTEA     NOT NULL,
  salt                BYTEA     NOT NULL,
  password_iterations INT4  NOT NULL,
  password_hint       TEXT,
  akey                TEXT     NOT NULL,
  private_key         TEXT,
  public_key          TEXT,
  totp_secret         TEXT,
  totp_recover        TEXT,
  security_stamp      TEXT     NOT NULL,
  equivalent_domains  TEXT     NOT NULL,
  excluded_globals    TEXT     NOT NULL,
  client_kdf_type     INT4 NOT NULL DEFAULT 0,
  client_kdf_iter     INT4 NOT NULL DEFAULT 100000,

  verified_at         TIMESTAMP DEFAULT NULL,
  last_verifying_at   TIMESTAMP DEFAULT NULL,
  login_verify_count  INT4 NOT NULL DEFAULT 0,
  email_new           VARCHAR(255) DEFAULT NULL,
  email_new_token     VARCHAR(16) DEFAULT NULL,
  enabled             BOOLEAN NOT NULL DEFAULT true,
  stamp_exception     TEXT DEFAULT NULL,
  api_key             TEXT,
  avatar_color        TEXT,
  client_kdf_memory       INT4 DEFAULT NULL,
  client_kdf_parallelism  INT4 DEFAULT NULL,
  external_id             TEXT
);

CREATE TABLE devices (
  uuid          VARCHAR(40) NOT NULL,
  created_at    TIMESTAMP NOT NULL,
  updated_at    TIMESTAMP NOT NULL,
  user_uuid     VARCHAR(40) NOT NULL REFERENCES users (uuid),
  name          TEXT NOT NULL,
  atype         INT4 NOT NULL,
  push_token    TEXT,
  refresh_token TEXT NOT NULL,

  twofactor_remember TEXT,
  push_uuid          TEXT,

  PRIMARY KEY (uuid, user_uuid)
);

CREATE TABLE organizations (
  uuid          VARCHAR(40) NOT NULL PRIMARY KEY,
  name          TEXT NOT NULL,
  billing_email TEXT NOT NULL,

  private_key   TEXT,
  public_key    TEXT,
  external_id   TEXT UNIQUE DEFAULT NULL
);

CREATE TABLE ciphers (
  uuid              VARCHAR(40) NOT NULL PRIMARY KEY,
  created_at        TIMESTAMP NOT NULL,
  updated_at        TIMESTAMP NOT NULL,
  user_uuid         VARCHAR(40) REFERENCES users (uuid),
  organization_uuid VARCHAR(40) REFERENCES organizations (uuid),
  atype             INT4  NOT NULL,
  name              TEXT     NOT NULL,
  notes             TEXT,
  fields            TEXT,
  data              TEXT     NOT NULL,
  password_history  TEXT,
  deleted_at        TIMESTAMP,
  reprompt          INT4,
  "key"             TEXT
);

CREATE TABLE attachments (
  id          TEXT NOT NULL PRIMARY KEY,
  cipher_uuid VARCHAR(40) NOT NULL REFERENCES ciphers (uuid),
  file_name   TEXT NOT NULL,
  file_size   BIGINT NOT NULL,
  akey        TEXT
);

CREATE TABLE folders (
  uuid       VARCHAR(40) NOT NULL PRIMARY KEY,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  user_uuid  VARCHAR(40) NOT NULL REFERENCES users (uuid),
  name       TEXT     NOT NULL
);

CREATE TABLE collections (
  uuid     VARCHAR(40) NOT NULL PRIMARY KEY,
  org_uuid VARCHAR(40) NOT NULL REFERENCES organizations (uuid),
  name     TEXT NOT NULL,

  external_id TEXT
);

CREATE TABLE users_collections (
  user_uuid       VARCHAR(40) NOT NULL REFERENCES users (uuid),
  collection_uuid VARCHAR(40) NOT NULL REFERENCES collections (uuid),
  read_only       BOOLEAN NOT NULL DEFAULT false,
  hide_passwords  BOOLEAN NOT NULL DEFAULT FALSE,
  manage          BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (user_uuid, collection_uuid)
);

CREATE TABLE users_organizations (
  uuid       VARCHAR(40) NOT NULL PRIMARY KEY,
  user_uuid  VARCHAR(40) NOT NULL REFERENCES users (uuid),
  org_uuid   VARCHAR(40) NOT NULL REFERENCES organizations (uuid),

  access_all BOOLEAN NOT NULL,
  akey       TEXT    NOT NULL,
  status     INT4 NOT NULL,
  atype      INT4 NOT NULL,

  reset_password_key TEXT,
  external_id TEXT,
  invited_by_email TEXT DEFAULT NULL,

  UNIQUE (user_uuid, org_uuid)
);

CREATE TABLE folders_ciphers (
  cipher_uuid VARCHAR(40) NOT NULL REFERENCES ciphers (uuid),
  folder_uuid VARCHAR(40) NOT NULL REFERENCES folders (uuid),
  PRIMARY KEY (cipher_uuid, folder_uuid)
);

CREATE TABLE ciphers_collections (
  cipher_uuid       VARCHAR(40) NOT NULL REFERENCES ciphers (uuid),
  collection_uuid VARCHAR(40) NOT NULL REFERENCES collections (uuid),
  PRIMARY KEY (cipher_uuid, collection_uuid)
);

CREATE TABLE twofactor (
  uuid      VARCHAR(40) NOT NULL PRIMARY KEY,
  user_uuid VARCHAR(40) NOT NULL REFERENCES users (uuid),
  atype     INT4  NOT NULL,
  enabled   BOOLEAN  NOT NULL,
  data      TEXT     NOT NULL,
  last_used BIGINT NOT NULL DEFAULT 0,

  UNIQUE (user_uuid, atype)
);

CREATE TABLE invitations (
    email   TEXT NOT NULL PRIMARY KEY
);
