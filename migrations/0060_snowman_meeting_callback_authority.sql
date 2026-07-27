-- Exact callback authority and digest-only evidence scope. Provider callbacks
-- are accepted only for one tenant, workspace, governed meeting, Snowman
-- workload identity, and operations-owned binding. Raw callback bodies, audio,
-- transcripts, dial coordinates, and provider credentials remain prohibited.

ALTER TABLE snowman_meeting_media_callback_bindings
    ADD COLUMN workspace_id UUID,
    ADD COLUMN meeting_id UUID,
    ADD COLUMN gateway_service_identity_id UUID,
    ADD COLUMN data_class TEXT CHECK (
        data_class IS NULL OR data_class IN ('internal','confidential')
    );

ALTER TABLE snowman_meeting_media_callback_bindings
    ADD CONSTRAINT snowman_meeting_media_callback_meeting_fk
        FOREIGN KEY (community_id, meeting_id)
        REFERENCES snowman_meetings(community_id, meeting_id);

ALTER TABLE snowman_meeting_media_callback_bindings
    ADD CONSTRAINT snowman_meeting_media_callback_identity_fk
        FOREIGN KEY (community_id, gateway_service_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id);

ALTER TABLE snowman_meeting_media_callback_bindings
    ADD CONSTRAINT snowman_meeting_media_callback_active_authority CHECK (
        status <> 'active' OR (
            workspace_id IS NOT NULL AND meeting_id IS NOT NULL AND
            gateway_service_identity_id IS NOT NULL AND data_class IS NOT NULL
        )
    );

CREATE UNIQUE INDEX snowman_meeting_media_callback_exact_authority
    ON snowman_meeting_media_callback_bindings(
        community_id, workspace_id, meeting_id, gateway_service_identity_id,
        provider, callback_binding_id
    );

ALTER TABLE snowman_meeting_media_webhook_receipts
    ADD COLUMN workspace_id UUID,
    ADD COLUMN meeting_id UUID,
    ADD COLUMN gateway_service_identity_id UUID,
    ADD COLUMN callback_binding_id UUID;

ALTER TABLE snowman_meeting_media_webhook_receipts
    ADD CONSTRAINT snowman_meeting_media_webhook_binding_fk
        FOREIGN KEY (community_id, callback_binding_id)
        REFERENCES snowman_meeting_media_callback_bindings(
            community_id, callback_binding_id
        );

ALTER TABLE snowman_meeting_media_webhook_receipts
    ADD CONSTRAINT snowman_meeting_media_webhook_scope_pair CHECK (
        (workspace_id IS NULL AND meeting_id IS NULL AND
         gateway_service_identity_id IS NULL AND callback_binding_id IS NULL) OR
        (workspace_id IS NOT NULL AND meeting_id IS NOT NULL AND
         gateway_service_identity_id IS NOT NULL AND callback_binding_id IS NOT NULL)
    );

CREATE INDEX snowman_meeting_media_webhook_exact_authority
    ON snowman_meeting_media_webhook_receipts(
        community_id, workspace_id, meeting_id, gateway_service_identity_id,
        callback_binding_id, received_at
    ) WHERE callback_binding_id IS NOT NULL;
