use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair, Signature, UnparsedPublicKey, ED25519};
use std::borrow::Borrow;

fn generate_keypair() -> Ed25519KeyPair {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("Failed to generate key pair");

    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("Failed to create key pair");
    return key_pair;
}

fn sign_data(key_pair: &Ed25519KeyPair,data: &[u8]) -> Signature {

    // Sign the data
    let signature = key_pair.sign(data);
    return signature;
}

fn verify_signature(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), ring::error::Unspecified> {
    let public_key = UnparsedPublicKey::new(&ED25519, public_key);
    public_key.verify(data, signature)
}



fn encrypt_data(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let sealing_key = aead::UnboundKey::new(&aead::AES_256_GCM, key).expect("Key creation failed");
    let sealing_key = aead::LessSafeKey::new(sealing_key);

    let tag_len = aead::AES_256_GCM.tag_len();  // Get the tag length at runtime
    let mut in_out = plaintext.to_vec();
    in_out.extend_from_slice(&vec![0u8; tag_len]); // Extend by tag length

    sealing_key.seal_in_place_append_tag(aead::Nonce::try_assume_unique_for_key(nonce).unwrap(), aead::Aad::empty(), &mut in_out)
        .expect("Encryption failed");

    in_out
}

fn decrypt_data(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let opening_key = aead::UnboundKey::new(&aead::AES_256_GCM, key).expect("Key creation failed");
    let opening_key = aead::LessSafeKey::new(opening_key);

    let mut in_out = ciphertext.to_vec();
    opening_key.open_in_place(aead::Nonce::try_assume_unique_for_key(nonce).unwrap(), aead::Aad::empty(), &mut in_out)
        .expect("Decryption failed");

    in_out
}

fn main() {
    let data = b"important message";

    let key_pair: Ed25519KeyPair = generate_keypair();

    // Sign the data
    let signature = sign_data(key_pair.borrow() ,data);

    // Verify the signature
    let result = verify_signature(key_pair.public_key().as_ref(), data, signature.as_ref());

    println!("Verification result: {:?}", result);


    let rng = SystemRandom::new();

    let mut key = [0u8; 32]; // 256-bit key
    rng.fill(&mut key).expect("Failed to generate key");

    let mut nonce: [u8; 12] = [0u8; 12]; // 96-bit nonce
    rng.fill(&mut nonce).expect("Failed to generate nonce");

    let plaintext = b"secret message";

    let encrypted = encrypt_data(&key, &nonce, plaintext);
    let decrypted = decrypt_data(&key, &nonce, &encrypted);

    println!("Plaintext: {:?}", plaintext);
    println!("Encrypted: {:?}", encrypted);
    println!("Decrypted: {:?}", decrypted);
}
