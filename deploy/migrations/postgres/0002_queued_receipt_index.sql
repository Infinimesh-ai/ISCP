-- MarkMessageDelivered matches pending receipts by domain and message. Keep
-- retained receipt history out of that per-message delivery lookup.
CREATE INDEX IF NOT EXISTS idx_relay_receipts_queued_message
ON iscp_relay.delivery_receipts (domain_id, message_id)
WHERE status = 'queued';
