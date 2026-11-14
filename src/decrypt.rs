//! The OpenPGP card's decryption slot as an X25519 key-agreement device:
//! read its public key, generate one on the card (touch fixed), and run
//! ECDH (PSO:DECIPHER) after a User PIN check (PW1 mode 82). Used by
//! aivyx-pa's card unlock; knows nothing about it.

use openpgp_card::{
    Card,
    ocard::{
        KeyType, StatusBytes,
        algorithm::{AlgoSimple, AlgorithmAttributes, Curve},
        crypto::{Cryptogram, EccType, PublicKeyMaterial},
        data::TouchPolicy,
    },
    state::{Admin, Transaction},
};
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{YubiError, provision::PublicKeyBytes};

/// A 32-byte X25519 shared secret, zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

fn x25519_point(material: PublicKeyMaterial) -> Result<PublicKeyBytes, YubiError> {
    match material {
        PublicKeyMaterial::E(ecc) => {
            let is_x25519 = matches!(
                ecc.algo(),
                AlgorithmAttributes::Ecc(a) if a.ecc_type() == EccType::ECDH && *a.curve() == Curve::Curve25519
            );
            if !is_x25519 {
                return Err(YubiError::UnsupportedDecryptionKey(format!(
                    "the decryption slot holds a {:?} key, not X25519",
                    ecc.algo()
                )));
            }
            let bytes: [u8; 32] = ecc.data().try_into().map_err(|_| {
                YubiError::UnsupportedDecryptionKey(format!(
                    "the decryption key is {} bytes, expected 32 (X25519)",
                    ecc.data().len()
                ))
            })?;
            Ok(PublicKeyBytes::new(bytes))
        }
        PublicKeyMaterial::R(_) => Err(YubiError::UnsupportedDecryptionKey(
            "the decryption slot holds an RSA key, not X25519".into(),
        )),
    }
}

/// The decryption slot's X25519 public key; `None` when the slot is empty.
pub fn decryption_public_key(
    tx: &mut Card<Transaction<'_>>,
) -> Result<Option<PublicKeyBytes>, YubiError> {
    match tx.public_key_material(KeyType::Decryption) {
        Ok(m) => x25519_point(m).map(Some),
        Err(openpgp_card::Error::CardStatus(StatusBytes::ReferencedDataNotFound)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Generate an X25519 key on the card, refusing if the slot holds one.
pub fn generate_decryption_key(
    admin: &mut Card<Admin<'_, '_>>,
) -> Result<PublicKeyBytes, YubiError> {
    match admin
        .as_transaction()
        .public_key_material(KeyType::Decryption)
    {
        Ok(_) => return Err(YubiError::DecryptionSlotOccupied),
        Err(openpgp_card::Error::CardStatus(StatusBytes::ReferencedDataNotFound)) => {}
        Err(e) => return Err(e.into()),
    }
    generate_decryption_key_overwriting(admin)
}

/// [`generate_decryption_key`] without the check: destroys any key there.
pub fn generate_decryption_key_overwriting(
    admin: &mut Card<Admin<'_, '_>>,
) -> Result<PublicKeyBytes, YubiError> {
    admin
        .set_algorithm(KeyType::Decryption, AlgoSimple::Curve25519)
        .map_err(crate::provision::map_admin_op_error)?;
    let (material, _) = admin
        .generate_key(crate::provision::key_slot_fingerprint, KeyType::Decryption)
        .map_err(crate::provision::map_admin_op_error)?;
    let public = x25519_point(material)?;
    admin
        .set_touch_policy(KeyType::Decryption, TouchPolicy::Fixed)
        .map_err(crate::provision::map_admin_op_error)?;
    Ok(public)
}

/// X25519 between the card's decryption key and `their_public`, on the
/// card: verifies the User PIN (mode 82), then PSO:DECIPHER, which waits
/// for a touch when the slot's touch policy is on.
pub fn ecdh(
    tx: &mut Card<Transaction<'_>>,
    pin: SecretString,
    their_public: &[u8; 32],
) -> Result<SharedSecret, YubiError> {
    if pin.expose_secret().is_empty() {
        return Err(YubiError::EmptyPin);
    }
    if decryption_public_key(tx)?.is_none() {
        return Err(YubiError::UnsupportedDecryptionKey(
            "the card's decryption slot is empty".into(),
        ));
    }
    tx.verify_user_pin(pin).map_err(|e| match e {
        openpgp_card::Error::CardStatus(StatusBytes::AuthenticationMethodBlocked) => {
            YubiError::PinBlocked {
                pin_kind: "User",
                recovery_hint: "Unblock it with the Admin PIN (RESET RETRY COUNTER).",
            }
        }
        other => other.into(),
    })?;
    let out = tx
        .card()
        .decipher(Cryptogram::ECDH(their_public))
        .map_err(crate::sign::map_sign_error)?;
    let bytes: [u8; 32] = out.as_slice().try_into().map_err(|_| {
        YubiError::Other(format!(
            "the card returned {} bytes for ECDH, expected 32",
            out.len()
        ))
    })?;
    Ok(SharedSecret(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeCard;
    use openpgp_card::Card;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn pin() -> SecretString {
        SecretString::from("123456")
    }

    #[test]
    fn an_empty_slot_has_no_public_key() {
        let mut card = Card::new(FakeCard::new()).unwrap();
        let mut tx = card.transaction().unwrap();
        assert!(decryption_public_key(&mut tx).unwrap().is_none());
    }

    #[test]
    fn an_existing_x25519_key_is_read() {
        let fake = FakeCard::new().with_decryption_key([5u8; 32]);
        let want = fake.decryption_public().unwrap();
        let mut card = Card::new(fake).unwrap();
        let mut tx = card.transaction().unwrap();
        assert_eq!(
            <[u8; 32]>::from(decryption_public_key(&mut tx).unwrap().unwrap()),
            want
        );
    }

    #[test]
    fn an_rsa_key_is_unsupported() {
        let mut card = Card::new(FakeCard::new().with_rsa_decryption_key()).unwrap();
        let mut tx = card.transaction().unwrap();
        assert!(matches!(
            decryption_public_key(&mut tx),
            Err(YubiError::UnsupportedDecryptionKey(_))
        ));
    }

    #[test]
    fn generate_makes_an_x25519_key_with_touch_fixed_and_refuses_a_second() {
        use openpgp_card::ocard::data::TouchPolicy;
        let fake = FakeCard::new();
        let probe = fake.clone();
        let mut card = Card::new(fake).unwrap();
        let mut tx = card.transaction().unwrap();
        let mut admin = tx.as_admin_card(SecretString::from("12345678")).unwrap();
        let public = generate_decryption_key(&mut admin).unwrap();
        assert_eq!(Some(<[u8; 32]>::from(public)), probe.decryption_public());
        assert!(matches!(
            generate_decryption_key(&mut admin),
            Err(YubiError::DecryptionSlotOccupied)
        ));
        let uif = admin
            .as_transaction()
            .user_interaction_flag(openpgp_card::ocard::KeyType::Decryption)
            .unwrap()
            .unwrap();
        assert_eq!(uif.touch_policy(), TouchPolicy::Fixed);
    }

    #[test]
    fn ecdh_matches_the_math_and_a_wrong_pin_is_refused() {
        let fake = FakeCard::new().with_decryption_key([5u8; 32]);
        let card_pub = fake.decryption_public().unwrap();
        let mut card = Card::new(fake).unwrap();
        let mut tx = card.transaction().unwrap();
        let eph = StaticSecret::from([8u8; 32]);
        let eph_pub = *PublicKey::from(&eph).as_bytes();
        let shared = ecdh(&mut tx, pin(), &eph_pub).unwrap();
        assert_eq!(
            shared.as_bytes(),
            eph.diffie_hellman(&PublicKey::from(card_pub)).as_bytes()
        );
        assert!(matches!(
            ecdh(&mut tx, SecretString::from("000000"), &eph_pub),
            Err(YubiError::PinIncorrect)
        ));
        assert!(matches!(
            ecdh(&mut tx, SecretString::from(""), &eph_pub),
            Err(YubiError::EmptyPin)
        ));
    }

    #[test]
    fn ecdh_without_a_key_says_so_and_a_touch_timeout_maps() {
        let mut card = Card::new(FakeCard::new()).unwrap();
        let mut tx = card.transaction().unwrap();
        assert!(matches!(
            ecdh(&mut tx, pin(), &[1u8; 32]),
            Err(YubiError::UnsupportedDecryptionKey(_))
        ));
        let mut card = Card::new(
            FakeCard::new()
                .with_decryption_key([5u8; 32])
                .with_touch_timeout(),
        )
        .unwrap();
        let mut tx = card.transaction().unwrap();
        assert!(matches!(
            ecdh(&mut tx, pin(), &[1u8; 32]),
            Err(YubiError::TouchTimeout)
        ));
    }
}
