-- deploy: post
-- Constraints for the 0095 SIEM columns. Post-deploy: the pre-deploy allow-list refuses CHECK.
-- The gateway only ever writes values inside these bounds; this is the database's backstop.
ALTER TABLE otel_exports ADD CONSTRAINT otel_exports_format_check CHECK (format IN ('otlp','splunk','sentinel','ocsf'));
ALTER TABLE otel_exports ADD CONSTRAINT otel_exports_delivery_attempts_check CHECK (delivery_attempts >= 0);
