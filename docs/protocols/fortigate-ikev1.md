# FortiGate dial-up IPsec (IKEv1)

How Polytunnel speaks to a FortiGate "remote access / FortiClient" IPsec tunnel. The engine
is `crates/polytunnel-ike` (protocol, no I/O) driven by `crates/polytunnel-daemon/src/ipsec.rs`
(sockets, TUN, network plan). Written from the RFCs; checked against strongSwan in CI
(`.github/workflows/interop.yml`).

## What a FortiClient tunnel negotiates

| Setting | FortiClient / FortiGate | Polytunnel default |
|---|---|---|
| IKE version, mode | IKEv1 aggressive mode | same (main mode and IKEv2 are not supported yet) |
| Authentication | pre-shared key, then XAuth username/password (method 65001) | same; `xauth = false` for plain PSK |
| Phase 1 | AES-CBC + SHA-1/SHA-2, one DH group (14 by default) | `aes256-sha256`, `aes128-sha256`, `aes256-sha1`, `aes128-sha1` with `dh-group` |
| Addressing | mode-config (address, DNS, split networks via Cisco Unity attributes) | pull (`mode-config = "push"` waits for the gateway) |
| Phase 2 | ESP tunnel mode, PFS with the phase-1 group, 43200 s | AES-CBC/HMAC and AES-GCM proposals, PFS on |
| NAT traversal | RFC 3947, keepalive every 5 s | always on (see below) |
| Dead-peer detection | RFC 3706 | after 20 s idle, 5 tries 5 s apart |

## The exchanges

1. **Aggressive mode** (UDP 500, from an ephemeral port).
   - `HDR, SA, KE, Ni, IDii, VIDs`. Vendor IDs announce XAuth, Cisco Unity, DPD and
     NAT-T (RFC 3947 and draft 02). Every transform carries the same DH group, because
     the key share already goes in this first message.
   - The gateway answers `HDR, SA, KE, Nr, IDir, HASH_R, VIDs, NAT-D, NAT-D`.
   - We send `HDR, HASH_I, NAT-D, NAT-D`, already on port 4500 with the four-byte non-ESP
     marker, followed by an encrypted INITIAL-CONTACT notification.
   - Keys follow RFC 2409:
     - SKEYID = prf(PSK, Ni_b | Nr_b);
     - SKEYID_d, SKEYID_a and SKEYID_e;
     - the cipher key comes from SKEYID_e, expanded per appendix B when it is too short;
     - IV = hash(g^xi | g^xr).
2. **XAuth** (transaction exchange, started by the gateway).
   - The gateway sends REQUEST(XAUTH_TYPE, USER_NAME, USER_PASSWORD). Polytunnel answers
     the first round from the profile.
   - Later rounds (FortiToken codes, new PIN, ...) become a prompt in the app. The daemon
     reports `needs-input`, and the app answers with an `answer` request.
   - The gateway's SET(XAUTH_STATUS) gets an ACK. Status 0 means a wrong username,
     password or code.
3. **Mode-config.**
   - Pull: we send REQUEST(INTERNAL_IP4_ADDRESS, ..., UNITY_SPLIT_INCLUDE,
     APPLICATION_VERSION) and the gateway answers with a REPLY.
   - Push: the gateway sends SET and we ACK it.
   - Split networks come from UNITY_SPLIT_INCLUDE (14-byte entries) or
     INTERNAL_IP4_SUBNET. Split DNS comes from UNITY_SPLIT_DNS_NAME and UNITY_DEF_DOMAIN.
4. **Quick mode.**
   - We send `HASH(1), SA, Ni, [KE], IDci, IDcr`:
     - the encapsulation mode is UDP-tunnel (3, or 61443 for the draft);
     - IDci is the assigned address;
     - IDcr is the profile's remote network, `0.0.0.0/0` unless set.
   - HASH(2) covers Ni_b and the rest of the reply, and we confirm with
     HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b).
   - KEYMAT = prf(SKEYID_d, [g(qm)^xy |] 3 | SPI | Ni_b | Nr_b), expanded. Each direction
     uses the receiver's SPI.
   - A RESPONDER-LIFETIME notification can shorten the lifetime.
5. **Afterwards.**
   - Polytunnel rekeys the ESP SAs with about 10% of their lifetime left. The replaced SA
     keeps receiving for 20 s, then is deleted.
   - When the gateway starts a quick mode itself, Polytunnel answers it as the responder.
   - DPD exchanges R-U-THERE and R-U-THERE-ACK, with the cookies as the SPI and a sequence
     number as the data.
   - Disconnecting deletes the ESP SAs and then the ISAKMP SA.
   - When the IKE SA reaches its lifetime (24 h by default), the connection ends. XAuth
     would be needed again.

## Forced NAT traversal

Our second NAT-D payload hashes a random address and port, so the gateway always believes we
are behind NAT. It then wraps ESP in UDP 4500 (RFC 3948), and the client never needs a raw
ESP socket.

Using one ephemeral UDP port for everything keeps Polytunnel clear of the Windows IKE
service and FortiClient, which hold ports 500 and 4500. The NAT keepalive (a single 0xFF
byte) keeps the mapping open, every 5 s by default.

## Importing from FortiClient (Windows)

FortiClient keeps tunnels under
`HKLM\SOFTWARE\Fortinet\FortiClient\IPSec\Tunnels\<name>\P1` and `...\P2`. Polytunnel reads
only non-secret values from there:

- `RemoteGW`, `User`, `LocalID`;
- `ikeversion`, `Aggressive`, `AuthMethod`, `XAuth`, `Modecfg`;
- `DHGroup`: a bit set in FortiClient's list order 1, 2, 5, 14, 15, 16, 17, 18, 19, 20,
  21. Check the imported group.
- `KeyLife`, `DPD`, `NatAliveFreq`, P2 `KeyLifeType`/`KeyLifeSec`/`KeyLifeKB` and
  `DIP`/`DMASK`.

The encrypted pre-shared key (`AuthKey`) is never read.

## Known gaps

- Main mode, certificates, IKEv2 + EAP and IPsec over TCP are not supported yet; IKEv2,
  EAP and IPsec over TCP are milestone M9.
- 3DES and DES are not offered.
- The IKE SA is not re-authenticated automatically.
