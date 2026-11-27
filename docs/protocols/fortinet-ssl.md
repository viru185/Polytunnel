# Fortinet SSL VPN (protocol notes)

Notes on the FortiGate SSL VPN exchange as implemented in `crates/polytunnel-forti`, written
from public documentation and observed protocol behaviour. All names and values below are
examples.

## 1. Login

`POST https://vpn.example.net:10443/remote/logincheck` with `ajax=1`, `username`, `realm` and
`credential`. The answer is a comma-separated status line:

* `ret=1,redir=…` plus `Set-Cookie: SVPNCOOKIE=…`: logged in.
* `ret=2,reqid=…,polid=…,grp=…,portal=…,magic=…,tokeninfo=…,chal_msg=…`: a token or one-time
  code is needed; the same fields (except `tokeninfo`, `chal_msg`, `ret`, `actionurl`) go back
  with `code=<code>` to `actionurl` (default `/remote/logincheck`).
* anything else, or an empty `SVPNCOOKIE`: rejected (`redir=…err=<reason>`).

## 2. Tunnel configuration

`GET /remote/fortisslvpn_xml` with `Cookie: SVPNCOOKIE=…` returns `<sslvpn-tunnel>` with, under
`<ipv4>`: `<assigned-addr ipv4="…"/>`, `<dns ip="…"/>`, `<dns-suffix>` (`;`-separated),
`<split-dns domains="…"/>`, and `<split-tunnel-info>` blocks of `<addr ip="…" mask="…"/>`
(`negate="1"`: networks to keep outside the tunnel). No split-tunnel info: full tunnel.

## 3. PPP over TLS

On a new TLS connection: `GET /remote/sslvpn-tunnel HTTP/1.1` with the cookie. There is no HTTP
answer; the connection carries PPP right away. Each PPP packet (starting with its protocol
field) is preceded by a 6-byte header: total length (2 bytes), `50 50`, PPP length (2 bytes).

PPP (RFC 1661, 1332, 1877):

* **LCP**: Polytunnel requests its MRU (1354) and a magic number; accepts the server's MRU,
  ACCM, magic number and the compression options; rejects anything else (e.g. authentication).
* **IPCP**: Polytunnel requests `0.0.0.0` for its address and DNS servers; the server's
  Configure-Nak carries the real values, which Polytunnel requests again; the link is up once
  both sides have acknowledged each other.
* Echo-Requests are answered and sent every 10 s; other protocols (e.g. IPv6CP) get a
  Protocol-Reject. Data uses protocol `0x0021` (IPv4) / `0x0057` (IPv6).
* Disconnect: LCP Terminate-Request, then `GET /remote/logout`.
