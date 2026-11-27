# GlobalProtect login (protocol notes)

Notes on the GlobalProtect login exchange as implemented in `crates/polytunnel-gp`. They are
written from public documentation and observed protocol behaviour. All hostnames and values
below are examples.

## Requests

Every request is a form `POST` with `User-Agent: PAN GlobalProtect` and these common fields:

| Field | Value |
|---|---|
| `clientVer` | `4100` |
| `clientos` | `Windows`, `Mac` or `Linux` (the real OS unless a profile overrides it) |
| `os-version` | e.g. `Microsoft Windows 11 Pro , 64-bit` |
| `computer` | the host name |
| `ipv6-support` | `yes` |
| `clientgpversion` | only if the profile sets `client-version` explicitly |

## 1. Portal pre-login

`POST https://portal.example.com/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Windows`
(gateways: `/ssl-vpn/prelogin.esp`). With `default-browser=1` the client says it can receive
the SAML result through the `globalprotectcallback:` link.

The `<prelogin-response>` carries `status`, and for SAML `saml-auth-method` (`REDIRECT` or
`POST`) and a base64 `saml-request` (an IdP URL, or an HTML page that posts a form). `region`
is the client's source region as the portal sees it (used for gateway priorities).

## 2. SAML in the browser

When the portal uses the system browser, the final page opens
`globalprotectcallback:<base64>`. The payload decodes to a small document:

```
<saml-auth-status>1</saml-auth-status>
<prelogin-cookie>…</prelogin-cookie>
<saml-username>user@example.com</saml-username>
```

Some portals send `portal-userauthcookie` instead of `prelogin-cookie`. Cloud Authentication
Service portals send `cas-as=1&un=<user>&token=<token>` (not supported yet).

Polytunnel registers itself for the link per user (`polytunnel uri register`), receives it in
`polytunnel --callback <link>`, and passes it over a per-user local socket to the waiting
`polytunnel auth`. `--paste` reads the link, page source or response headers from the terminal
instead.

## 3. Portal configuration

`POST /global-protect/getconfig.esp` with `user`, `passwd` (empty for SAML) and the proof:
`prelogin-cookie` or `portal-userauthcookie`. The `<policy>` answer lists gateways:

```
<gateways>
  <cutoff-time>5</cutoff-time>
  <external><list>
    <entry name="gw1.example.com">
      <priority-rule><entry name="Any"><priority>1</priority></entry></priority-rule>
      <priority>1</priority>
      <description>Site A</description>
    </entry>
  </list></external>
</gateways>
```

plus `portal-userauthcookie`, which usually lets the gateway accept the user without a second
login. HTTP 512 means the credentials or cookie were rejected.

## 4. Gateway login

`POST https://gw1.example.com/ssl-vpn/login.esp` with the portal cookie (or a gateway SAML
`prelogin-cookie`, or a password). The answer is a JNLP document whose `<argument>` list holds,
by position: 1 `authcookie`, 3 portal, 4 user, 7 domain, 12 connection type (`tunnel`),
15 preferred IPv4, 18 preferred IPv6.

The session cookie handed to the tunnel (and printed by `polytunnel auth --emit cookie`) is
`authcookie=…&portal=…&user=…&domain=…&computer=…&preferred-ip=…`, URL-encoded. `computer`
must match the value sent at login.

## 5. Tunnel configuration

`POST https://gw1.example.com/ssl-vpn/getconfig.esp` with the session fields and the ESP
algorithms Polytunnel supports (`enc-algo=aes-256-cbc,aes-128-cbc`, `hmac-algo=sha256,sha1`).
The `<response status="success">` holds `ip-address`, `netmask`, `mtu`, `dns/member`,
`dns-suffix/member`, `access-routes/member` (empty: full tunnel), `exclude-access-routes`,
`gw-address`, `ssl-tunnel-url` and, for ESP, an `<ipsec>` block: `udp-port`, `enc-algo`,
`hmac-algo`, `c2s-spi`, `s2c-spi` and the keys `ekey-c2s`, `akey-c2s`, `ekey-s2c`, `akey-s2c`
(each `<bits>` + hex `<val>`).

## 6. Data transport

* **ESP**: RFC 4303 tunnel mode over UDP to the gateway (`udp-port`, usually 4501). Polytunnel
  checks it with an ICMP echo through the tunnel and keeps it alive with periodic probes;
  if the gateway stops answering, it switches to TLS.
* **TLS**: `GET <ssl-tunnel-url>?user=…&authcookie=…`; the gateway answers `START_TUNNEL`.
  Each packet then carries a 16-byte header: `1a2b3c4d`, ethertype (`0800`/`86dd`), payload
  length, `01 00 00 00 00 00 00 00`. A header with ethertype and length zero is a keepalive.

## 7. HIP and logout

`/ssl-vpn/hipreportcheck.esp` (with the report's MD5) tells whether the gateway wants a host
report; `/ssl-vpn/hipreport.esp` submits it. Polytunnel's report contains host information only.
`/ssl-vpn/logout.esp` ends the session.
