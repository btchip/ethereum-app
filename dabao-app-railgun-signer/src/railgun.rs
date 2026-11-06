//! Railgun keys, as the Railgun engine derives them (Railway, the rsgun-wallet
//! mnemonic signer), and what the device answers with them.
//!
//! * Derivation: SLIP-0010, hardened only, HMAC-SHA512 keyed with
//!   `"babyjubjub seed"`, from the BIP-39 seed:
//!   spending `m/44'/1984'/0'/0'/account'`, viewing `m/420'/1984'/0'/0'/account'`.
//! * Spending: BabyJubJub, Poseidon-EdDSA as circomlib (`kohaku-crypto`).
//! * Viewing: the 32-byte derivation output is an ed25519 seed.
//! * Address: bech32m `0zk`, version 1 || MPK || network id || viewing public
//!   key, with MPK = Poseidon(spending x, spending y, Poseidon(viewing key)).
use ark_ff::{BigInteger, PrimeField};
use hmac::{Hmac, Mac};
use ruint::aliases::U256;
use sha2::Sha512;
use zeroize::Zeroizing;

const CURVE_SEED: &[u8] = b"babyjubjub seed";
const HARDENED: u32 = 0x8000_0000;
/// The network id of the chain-agnostic address ("all chains"), XORed with
/// `"railgun\0"` as in the address encoding.
const ALL_CHAINS: [u8; 8] = [0x8d, 0x9e, 0x96, 0x93, 0x98, 0x8a, 0x91, 0xff];

pub type Key = Zeroizing<[u8; 32]>;

fn hmac512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC takes any key");
    for p in parts {
        mac.update(p);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn derive(seed: &[u8; 64], path: &[u32]) -> Key {
    let mut node = hmac512(CURVE_SEED, &[seed]);
    for &i in path {
        let (key, chain) = node.split_at(32);
        node = hmac512(chain, &[&[0], key, &(i | HARDENED).to_be_bytes()]);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&node[..32]);
    key
}

pub fn spending_key(seed: &[u8; 64], account: u32) -> Key {
    derive(seed, &[44, 1984, 0, 0, account])
}

pub fn viewing_key(seed: &[u8; 64], account: u32) -> Key {
    derive(seed, &[420, 1984, 0, 0, account])
}

fn fr_bytes(f: ark_bn254::Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let be = f.into_bigint().to_bytes_be();
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// BabyJubJub public key, x || y big-endian.
pub fn spending_public_key(key: &Key) -> [u8; 64] {
    let p = kohaku_crypto::babyjubjub::PrivateKey::new(**key).public();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&fr_bytes(p.x));
    out[32..].copy_from_slice(&fr_bytes(p.y));
    out
}

pub fn viewing_public_key(key: &Key) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(key).verifying_key().to_bytes()
}

/// Poseidon-EdDSA of `hash` (big-endian): R8.x || R8.y || S, big-endian.
/// `None` if `hash` isn't a field element.
pub fn sign(key: &Key, hash: &[u8; 32]) -> Option<[u8; 96]> {
    let msg = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, hash);
    let sig = kohaku_crypto::babyjubjub::PrivateKey::new(**key).sign(msg).ok()?;
    let mut out = [0u8; 96];
    out[..32].copy_from_slice(&fr_bytes(sig.r_b8.x));
    out[32..64].copy_from_slice(&fr_bytes(sig.r_b8.y));
    let (_, s) = sig.s.to_bytes_be();
    out[96 - s.len()..].copy_from_slice(&s);
    Some(out)
}

fn poseidon(inputs: &[[u8; 32]]) -> [u8; 32] {
    let inputs: Vec<U256> = inputs.iter().map(|b| U256::from_be_bytes(*b)).collect();
    kohaku_crypto::poseidon_hash(&inputs).expect("poseidon of field elements").to_be_bytes()
}

/// The chain-agnostic `0zk1…` address.
pub fn address(spending_public: &[u8; 64], viewing: &Key) -> String {
    let nullifying = poseidon(&[**viewing]);
    let x: [u8; 32] = spending_public[..32].try_into().unwrap();
    let y: [u8; 32] = spending_public[32..].try_into().unwrap();
    let mpk = poseidon(&[x, y, nullifying]);
    let mut payload = Vec::with_capacity(73);
    payload.push(1);
    payload.extend_from_slice(&mpk);
    payload.extend_from_slice(&ALL_CHAINS);
    payload.extend_from_slice(&viewing_public_key(viewing));
    bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse_unchecked("0zk"), &payload).expect("bech32m")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-39 seed of "test test … junk" (empty passphrase).
    fn hardhat_seed() -> [u8; 64] {
        let entropy = [0xdf, 0x9b, 0xf3, 0x7e, 0x6f, 0xcd, 0xf9, 0xbf, 0x37, 0xe6, 0xfc, 0xdf, 0x9b, 0xf3, 0x7e, 0x3c];
        signer_signing::seed_from_entropy(&entropy, "").unwrap()
    }

    /// rsgun-wallet's `keys::tests` vectors (the Railgun engine's, chain-agnostic).
    #[test]
    fn addresses_match_the_engine() {
        let seed = hardhat_seed();
        let expected = [
            "0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48tlrv7j6fe3z53lama02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw5ajy990",
            "0zk1qy3v85v8p20nhh0ngjfzvtu6rn3gqyelkf637dr24vedl9c5n0xerrv7j6fe3z53lazlyh76vzhsd95mvzdeggp7jza7k4xvklx20sgxpp3dct6lww27572l9cd",
            "0zk1qykd7kxmknsa4twdfjry47u4vt8ajfv9dsy2ehqgt7a48mqkewtfhrv7j6fe3z53lu2xzw98f9pkyrcz9cfxya9xgjgnq6wcux50q5ha5v732x5xk3ku50stj3c",
            "0zk1qydxcqzgtapkzw7ennwuz30cmat3frvccymahqe379v3zr0yl5ddrrv7j6fe3z53luyla4cxkg3d9er5csdj8xnj6faxc3aey2ee0lxhpdu3er2a63vlqz6szxh",
        ];
        for (account, want) in expected.iter().enumerate() {
            let s = spending_key(&seed, account as u32);
            let v = viewing_key(&seed, account as u32);
            assert_eq!(address(&spending_public_key(&s), &v), *want, "account {account}");
        }
    }

    /// poseidon-rust's known answers for 1..5 inputs (0, 1, …), the widths the
    /// vendored copy keeps; 6 inputs are refused.
    #[test]
    fn poseidon_known_answers() {
        let expected = [
            "19014214495641488759237505126948346942972912379615652741039992445865937985820",
            "12583541437132735734108669866114103169564651237895298778035846191048104863326",
            "8599452571108419911675042369134657596129797276905188988960674134744449929238",
            "4050345352754260300667252706570081029004026400044882557845061748628670512780",
            "1475992993236322576209363326357087103599755887159177217587002895783839174540",
        ];
        for (n, want) in expected.iter().enumerate() {
            let inputs: Vec<U256> = (0..=n as u64).map(U256::from).collect();
            assert_eq!(kohaku_crypto::poseidon_hash(&inputs).unwrap().to_string(), *want);
        }
        assert!(kohaku_crypto::poseidon_hash(&[U256::ZERO; 6]).is_err());
    }

    #[test]
    fn signs_field_elements_only() {
        let key = spending_key(&hardhat_seed(), 0);
        let a = sign(&key, &[1; 32]).unwrap();
        assert_eq!(a, sign(&key, &[1; 32]).unwrap(), "deterministic");
        assert_ne!(a, sign(&key, &[2; 32]).unwrap());
        assert!(sign(&key, &[0xff; 32]).is_none(), "above the field modulus");
    }
}
