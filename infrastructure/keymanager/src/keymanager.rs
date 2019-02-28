use crypto::ristretto::RistrettoSecretKey as SecretKey;
use crypto::keys::SecretKeyFactory;
use crypto::common::ByteArray;
use rand;

use sha2::{Sha256, Digest};
use crypto::common::ByteArrayError;


pub fn sha256(input_vec: Vec<u8>) -> Vec<u8> {
    let mut h = Sha256::new();
    h.input(input_vec);
    (h.result().to_vec())
}

pub fn generate_private_key() -> SecretKey {
    let mut rng = rand::OsRng::new().unwrap();
    (SecretKey::random(&mut rng))
}


//Todo make master key
pub struct KeyManager {
    master_key: SecretKey,
}

impl KeyManager {

    pub fn new() -> KeyManager {
        KeyManager{master_key:generate_private_key()}
    }

    pub fn set_master_key_from_secret_key(&mut self, new_master_key: SecretKey) {
        self.master_key=new_master_key;
    }

    //pub fn set_master_key_from_mnemonic(master_key: SecretKey) {




    //}


    /*pub fn generate_master_key() -> SecretKey {
        let mut rng = rand::OsRng::new().unwrap();
        (SecretKey::random(&mut rng))
    }*/


    // Derived keys are generated as derived_key=SHA256(master_key||index)
    pub fn derive_key(&mut self,index: u64) -> Result<SecretKey, ByteArrayError> {
        let combined = format!("{}{}", self.master_key.to_hex(), index.to_string());
        (SecretKey::from_bytes(sha256(combined.into_bytes()).as_slice()))
    }
}


#[cfg(test)]
mod test {
    //use super::*;
    use keymanager::*;
    use crypto::common::ByteArray;

    #[test]
    fn test_master_key_derivation() {

        println!("stage 1");

        let mut k=KeyManager::new();

        println!("Keychain: {:?}",k.master_key);

        println!("SHA256: {:?}",sha256(k.master_key.to_vec()));

        println!("derive1: {:?}",k.derive_key(1));
        println!("derive2: {:?}",k.derive_key(2));
        println!("derive1: {:?}",k.derive_key(1));

        println!("stage 2");

        assert_eq!(0,1);
    }
}