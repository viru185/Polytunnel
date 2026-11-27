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
