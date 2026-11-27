//! MS-CHAPv2 ([RFC 2759]) and its key derivation ([RFC 3079]), as EAP-MSCHAPv2 uses them.
//!
//! [RFC 2759]: https://www.rfc-editor.org/rfc/rfc2759
//! [RFC 3079]: https://www.rfc-editor.org/rfc/rfc3079

use des::cipher::{BlockCipherEncrypt, KeyInit};
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

const MAGIC1: &[u8] = b"Magic server to client signing constant";
const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";
const MASTER_MAGIC: &[u8] = b"This is the MPPE Master Key";
const CLIENT_SEND: &[u8] =
    b"On the client side, this is the send key; on the server side, it is the receive key.";
const CLIENT_RECEIVE: &[u8] =
    b"On the client side, this is the receive key; on the server side, it is the send key.";

/// NtPasswordHash: MD4 of the UTF-16LE password.
pub fn password_hash(password: &str) -> Zeroizing<[u8; 16]> {
    let utf16: Zeroizing<Vec<u8>> =
        Zeroizing::new(password.encode_utf16().flat_map(u16::to_le_bytes).collect());
    let mut out = Zeroizing::new([0u8; 16]);
    out.copy_from_slice(&md4::Md4::digest(&*utf16));
    out
}

fn md4_of(data: &[u8]) -> Zeroizing<[u8; 16]> {
    let mut out = Zeroizing::new([0u8; 16]);
    out.copy_from_slice(&md4::Md4::digest(data));
    out
}

/// ChallengeHash: the first 8 bytes of SHA-1(PeerChallenge | AuthenticatorChallenge | UserName).
pub fn challenge_hash(peer: &[u8; 16], authenticator: &[u8; 16], username: &[u8]) -> [u8; 8] {
    let mut h = Sha1::new();
    h.update(peer);
    h.update(authenticator);
    h.update(username);
    h.finalize()[..8].try_into().expect("8 bytes")
}

/// Seven key bytes spread over eight DES key bytes (the parity bits are ignored by DES).
fn des_key(k: &[u8]) -> [u8; 8] {
    [
        k[0],
        (k[0] << 7) | (k[1] >> 1),
        (k[1] << 6) | (k[2] >> 2),
        (k[2] << 5) | (k[3] >> 3),
        (k[3] << 4) | (k[4] >> 4),
        (k[4] << 3) | (k[5] >> 5),
        (k[5] << 2) | (k[6] >> 6),
        k[6] << 1,
    ]
}

/// ChallengeResponse: the challenge DES-encrypted under the three thirds of the
/// zero-padded password hash.
fn challenge_response(challenge: &[u8; 8], hash: &[u8; 16]) -> [u8; 24] {
    let mut padded = Zeroizing::new([0u8; 21]);
    padded[..16].copy_from_slice(hash);
    let mut out = [0u8; 24];
    for i in 0..3 {
        let cipher =
            des::Des::new_from_slice(&des_key(&padded[i * 7..i * 7 + 7])).expect("8-byte DES key");
        let mut block = (*challenge).into();
        cipher.encrypt_block(&mut block);
        out[i * 8..i * 8 + 8].copy_from_slice(&block);
    }
    out
}

/// GenerateNTResponse.
pub fn nt_response(
    authenticator: &[u8; 16],
    peer: &[u8; 16],
    username: &[u8],
    password: &str,
) -> [u8; 24] {
    let challenge = challenge_hash(peer, authenticator, username);
    challenge_response(&challenge, &password_hash(password))
}

/// GenerateAuthenticatorResponse: the `S=<40 hex digits>` the server must send back.
pub fn authenticator_response(
    password: &str,
    nt_response: &[u8; 24],
    peer: &[u8; 16],
    authenticator: &[u8; 16],
    username: &[u8],
) -> String {
    let hash_hash = md4_of(&*password_hash(password));
    let digest = Sha1::new()
        .chain_update(*hash_hash)
        .chain_update(nt_response)
        .chain_update(MAGIC1)
        .finalize();
    let challenge = challenge_hash(peer, authenticator, username);
    let digest = Sha1::new()
        .chain_update(digest)
        .chain_update(challenge)
        .chain_update(MAGIC2)
        .finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02X}")).collect();
    format!("S={hex}")
}

/// The client's EAP-MSCHAPv2 MSK: its send key, then its receive key (RFC 3079 derivation).
pub fn msk(password: &str, nt_response: &[u8; 24]) -> Zeroizing<Vec<u8>> {
    let hash_hash = md4_of(&*password_hash(password));
    let master = Sha1::new()
        .chain_update(*hash_hash)
        .chain_update(nt_response)
        .chain_update(MASTER_MAGIC)
        .finalize();
    let start_key = |magic: &[u8]| {
        Sha1::new()
            .chain_update(&master[..16])
            .chain_update([0u8; 40])
            .chain_update(magic)
            .chain_update([0xf2u8; 40])
            .finalize()
    };
    let mut out = Zeroizing::new(Vec::with_capacity(32));
    out.extend_from_slice(&start_key(CLIENT_SEND)[..16]);
    out.extend_from_slice(&start_key(CLIENT_RECEIVE)[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 2759 section 9.2 sample data; RFC 3079 for the keys (recomputed independently).
    const AUTH: &str = "5B5D7C7D7B3F2F3E3C2C602132262628";
    const PEER: &str = "21402324255E262A28295F2B3A337C7E";

    #[test]
    fn rfc_2759_sample() {
        let auth: [u8; 16] = hex(AUTH).try_into().unwrap();
        let peer: [u8; 16] = hex(PEER).try_into().unwrap();
        let password = "clientPass";
        assert_eq!(
            &*password_hash(password),
            &hex("44EBBA8D5312B8D611474411F56989AE")[..]
        );
        assert_eq!(
            challenge_hash(&peer, &auth, b"User").to_vec(),
            hex("D02E4386BCE91226")
        );
        let nt = nt_response(&auth, &peer, b"User", password);
        assert_eq!(
            nt.to_vec(),
            hex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
        );
        assert_eq!(
            authenticator_response(password, &nt, &peer, &auth, b"User"),
            "S=407A5589115FD0D6209F510FE9C04566932CDA56"
        );
        assert_eq!(
            *msk(password, &nt),
            hex("D5F0E9521E3EA9589645E86051C822268B7CDC149B993A1BA118CB153F56DCCB")
        );
    }
}
