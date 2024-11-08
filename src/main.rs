use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
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

    /// Returns the public key as a point
    pub fn public_key_point(&self) -> Result<EcPoint, Box<dyn Error>> {
        let ec_key = self.public_key.ec_key()?;
        Ok(ec_key.public_key().to_owned())
    }

    /// Exports the public key in uncompressed format
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let group = EcGroup::from_curve_name(Nid::SECP256K1)?;
        let mut ctx = openssl::bn::BigNumContext::new()?;
        let point = self.public_key_point()?;
        let mut buf = Vec::new();
        buf.resize(group.degree() as usize / 8 + 1, 0);
        point.to_bytes(&group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut buf, &mut ctx)?;
        Ok(buf)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Generate ECC key pair
    let ecc_keypair = EccKeyPair::generate()?;

    // Message to be signed
    let message = b"Hello, ECC!";

    // Sign the message
    let signature = ecc_keypair.sign(message)?;
    println!("Signature: {:?}", signature);

    // Verify the signature
    let is_valid = ecc_keypair.verify(message, &signature)?;
    println!("Signature valid: {}", is_valid);

    Ok(())
}
