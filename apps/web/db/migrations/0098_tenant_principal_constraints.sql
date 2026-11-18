-- deploy: post
ALTER TABLE tenant_principal_issuers ADD CONSTRAINT tenant_principal_issuers_pk PRIMARY KEY (id);
ALTER TABLE tenant_principal_issuers ADD CONSTRAINT tenant_principal_issuers_tenant_issuer UNIQUE (tenant_id, issuer);
ALTER TABLE tenant_principal_issuers ADD CONSTRAINT tenant_principal_issuers_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
