# IKEv2, EAP and IPsec over TCP

FortiGate dial-up tunnels can also use IKEv2 (`ike-version = 2` in a Fortinet IPsec profile).

The implementation has three parts:

- `crates/polytunnel-ike/src/v2`: the IKEv2 protocol, with no I/O;
- `crates/polytunnel-ike/src/eap`: the EAP peer;
- `crates/polytunnel-ike/src/tcp.rs`: RFC 9329 framing.

The daemon drives them through the same session interface and engine as IKEv1. CI tests it
against strongSwan, plus libreswan for TCP (`.github/workflows/interop.yml`).

## Profile settings

| Setting | Values | Meaning |
|---|---|---|
| `ike-version` | `2` | Use IKEv2 instead of aggressive mode. |
| `eap` | `mschapv2`, `ttls-pap` | Sign in with the username and password over EAP. Without it, the pre-shared key authenticates us. |
| `server-auth` | `psk` (default), `certificate` | How the gateway proves itself. |
| `ca-file` | path to a PEM file | Extra CA certificates to trust, besides the system's roots. |
| `remote-id` | host name | The name the gateway's certificate, and an EAP-TTLS server's, must carry. Defaults to `server`. |
| `transport` | `udp` (default), `tcp` | `tcp` is FortiOS's "transport tcp" (RFC 9329). |
| `tcp-port` | port | The gateway's TCP port; default 443. |

The proposal settings (`dh-group`, `ike-proposals`, `esp-proposals`, `pfs-group`) and
lifetimes work as they do for IKEv1. IKE proposals may also use AES-GCM, for example
`aes256gcm16-prfsha256`.

## The exchanges

1. **IKE_SA_INIT** (UDP 500, or the TCP connection).
   - We send `SA, KE, Ni`, then NAT detection notifications. Our source hash describes an
     address we do not have, so NAT traversal is forced and ESP always travels in UDP 4500
     or in the TCP stream.
   - We also send `IKEV2_FRAGMENTATION_SUPPORTED` and, when a certificate is expected,
     `SIGNATURE_HASH_ALGORITHMS`.
   - A `COOKIE` or `INVALID_KE_PAYLOAD` reply is followed by a new request.
   - Keys: SKEYSEED = prf(Ni | Nr, g^ir), then prf+ gives SK_d, SK_ai/ar, SK_ei/er and
     SK_pi/pr.
2. **IKE_AUTH**.
   - We send `IDi, [AUTH], CP(CFG_REQUEST), SA, TSi, TSr, N(INITIAL_CONTACT)`. TSr is the
     profile's remote network.
   - With a pre-shared key, AUTH = prf(prf(PSK, "Key Pad for IKEv2"), \<SignedOctets\>).
   - With EAP there is no AUTH yet:
     1. The gateway first proves itself, with a PSK or with its certificate:
        - the chain must lead to a trusted CA;
        - the certificate must be issued for `remote-id`;
        - its EKU must be serverAuth or ipsecIKE;
        - accepted signatures: RSA, ECDSA with raw r‖s, and RFC 7427 digital signatures.
     2. Then EAP runs, one EAP message per IKE_AUTH round.
     3. Finally, both sides send an AUTH made with the MSK.
   - The reply carries:
     - CP(CFG_REPLY): address, DNS servers, split networks and DNS domains (RFC 8598);
     - the narrowed TSr, which adds split routes;
     - the child SA.
3. **Child SAs.**
   - KEYMAT = prf+(SK_d, [g^ir] | Ni | Nr). The keys for the direction from the exchange's
     initiator to its responder come first.
   - Rekeying uses CREATE_CHILD_SA with REKEY_SA, plus a fresh key exchange when PFS is on.
   - Polytunnel rekeys with about 10% of the lifetime left, and answers the gateway's
     rekeys.
   - A replaced SA is deleted after 20 seconds.
4. **Informational exchanges.**
   - Liveness checks: an empty INFORMATIONAL request when the tunnel has been quiet for the
     DPD interval.
   - The gateway's deletes are answered.
   - On disconnect we send DELETE for the IKE SA.
   - Requests go one at a time; others wait in a queue.

Fragmented replies (SKF payloads, RFC 7383) are reassembled; we never need to fragment our
own messages.

## EAP methods

- **EAP-MSCHAPv2**: RFC 2759, with the MSK derived per RFC 3079. The MSK is the client's
  send key followed by its receive key, 32 bytes.
- **EAP-TTLS with PAP**: RFC 5281.
  - TLS 1.2 runs in memory (rustls), with fragmentation and acknowledgements both ways.
  - The TTLS server's certificate is checked with the same trust as the gateway.
  - The username and password are sent as User-Name and User-Password AVPs inside the
    tunnel.
  - The MSK is the TLS export with the label "ttls keying material".

## IPsec over TCP (RFC 9329)

- The connection starts with `IKETCP`.
- After that, each message is a 2-byte length followed by either an IKE message (behind
  four zero bytes) or an ESP packet.
- Over TCP nothing is retransmitted. A request that gets no answer within 30 s ends the
  connection.

## Known gaps

- The IKE SA itself is not rekeyed. The session ends at its lifetime and the gateway's IKE
  rekeys are declined; connect again.
- MOBIKE, certificate client authentication, EAP-TLS and TTLS with MSCHAPv2 inside are not
  supported.
