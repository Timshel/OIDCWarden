ALTER TABLE organizations ADD COLUMN external_id TEXT DEFAULT NULL;
CREATE UNIQUE INDEX organizations_external_id ON organizations(external_id);
