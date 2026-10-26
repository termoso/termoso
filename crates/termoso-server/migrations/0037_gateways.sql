-- Gateways: an API bridge running `termoso-bridge gateway` keeps an outbound
-- WebSocket to the server and dials hosts on its own network for members who
-- share a vault with it. The server relays opaque SSH bytes and never learns
-- the host address (clients name hosts by vault/entity id; the gateway resolves
-- them from the vault it already holds). Online = seen within 90 s.
ALTER TABLE bridges ADD COLUMN gateway_seen_at timestamptz;
