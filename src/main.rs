use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::symm::Cipher;
use openssl::derive::Deriver;
use openssl::sign::{Signer, Verifier};
use aes_gcm::aead::{Aead, KeyInit, OsRng, generic_array::GenericArray};
use aes_gcm::{Aes256Gcm, Nonce}; // AES-GCM 256-bit variant
use std::error::Error;

pub struct EccKeyPair {
    private_key: PKey<Private>,
    public_key: PKey<Public>,
}

impl EccKeyPair {
    /// Generates a new ECC key pair
    pub fn generate() -> Result<Self, Box<dyn Error>> {
        let group = EcGroup::from_curve_name(Nid::SECP256K1)?;
        let ec_key = EcKey::generate(&group)?;
        let private_key = PKey::from_ec_key(ec_key.clone())?;
        let public_key = PKey::from_ec_key(EcKey::from_public_key(&group, ec_key.public_key())?)?;

        Ok(EccKeyPair { private_key, public_key })
    }

    /// Signs data using the private key
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut signer = Signer::new_without_digest(&self.private_key)?;
        signer.update(data)?;
        let signature = signer.sign_to_vec()?;
        Ok(signature)
    }

    /// Verifies a signature using the public key
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Box<dyn Error>> {
        let mut verifier = Verifier::new_without_digest(&self.public_key)?;
        verifier.update(data)?;
        Ok(verifier.verify(signature)?)
    }

    /// Derives a shared secret using ECDH
    pub fn derive_shared_secret(&self, peer_public_key: &PKey<Public>) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut deriver = Deriver::new(&self.private_key)?;
        deriver.set_peer(peer_public_key)?;
        let shared_secret = deriver.derive_to_vec()?;
        Ok(shared_secret)
    }

    /// Encrypts data using AES-GCM with a derived shared secret
    pub fn encrypt(&self, peer_public_key: &PKey<Public>, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // Derive the shared secret
        let shared_secret = self.derive_shared_secret(peer_public_key)?;

        // Use the first 32 bytes of the shared secret as the AES key
        let key = GenericArray::from_slice(&shared_secret[..32]);
        let cipher = Aes256Gcm::new(key);

        // Generate a random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

        // Encrypt the data
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;
        
        // Prepend nonce to ciphertext for use in decryption
        Ok([nonce.as_slice(), &ciphertext].concat())
    }

    /// Decrypts data using AES-GCM with a derived shared secret
    pub fn decrypt(&self, peer_public_key: &PKey<Public>, ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // Derive the shared secret
        let shared_secret = self.derive_shared_secret(peer_public_key)?;

        // Use the first 32 bytes of the shared secret as the AES key
        let key = GenericArray::from_slice(&shared_secret[..32]);
        let cipher = Aes256Gcm::new(key);

        // Split the nonce and ciphertext
        let (nonce, ciphertext) = ciphertext_with_nonce.split_at(12); // 12 bytes for nonce in AES-GCM

        // Decrypt the data
        let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)?;
        Ok(plaintext)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Generate ECC key pairs for two parties
    let alice_keypair = EccKeyPair::generate()?;
    let bob_keypair = EccKeyPair::generate()?;

    // Encrypt a message from Alice to Bob
    let message = b"Hello, Bob!";
    let ciphertext = alice_keypair.encrypt(&bob_keypair.public_key, message)?;
    println!("Ciphertext: {:?}", ciphertext);

    // Decrypt the message on Bob's side
    let decrypted_message = bob_keypair.decrypt(&alice_keypair.public_key, &ciphertext)?;
    println!("Decrypted message: {:?}", String::from_utf8(decrypted_message)?);

    Ok(())
}
