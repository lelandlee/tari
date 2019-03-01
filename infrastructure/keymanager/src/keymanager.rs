use crypto::common::ByteArray;
use crypto::keys::SecretKeyFactory;
use crypto::ristretto::RistrettoSecretKey as SecretKey;
use rand;

use crypto::common::ByteArrayError;
use sha2::{Digest, Sha256};

pub fn sha256(input_vec: Vec<u8>) -> Vec<u8> {
    let mut h = Sha256::new();
    h.input(input_vec);
    (h.result().to_vec())
}

pub fn generate_private_key() -> SecretKey {
    let mut rng = rand::OsRng::new().unwrap();
    (SecretKey::random(&mut rng))
}

pub struct KeyManager {
    master_key: SecretKey,
    derived_keys: Vec<SecretKey>,
}

impl KeyManager {
    pub fn new() -> KeyManager {
        KeyManager { master_key: generate_private_key(), derived_keys: Vec::new() }
    }

    pub fn from(master_key: SecretKey) -> KeyManager {
        KeyManager { master_key, derived_keys: Vec::new() }
    }

    pub fn from_seed(seed: String) -> KeyManager {
        KeyManager {
            master_key: SecretKey::from_bytes(sha256(seed.into_bytes()).as_slice()).unwrap(),
            derived_keys: Vec::new(),
        }
    }

    /*pub fn from_mnemonic(master_key: SecretKey) -> KeyManager {
        KeyManager { master_key, derived_keys: Vec::new() }
    }*/

    //TODO fix index out of order issue

    // Derived keys are generated as derived_key=SHA256(master_key||index)
    pub fn derive_key(&mut self, index: usize) -> Result<SecretKey, ByteArrayError> {
        //Check if key already derived and then return new or previously derived key
        if index < self.derived_keys.len() {
            Ok(self.derived_keys[index])
        } else {
            (self.derive_next_key())
        }
    }

    pub fn derive_next_key(&mut self) -> Result<SecretKey, ByteArrayError> {
        let index = self.derived_keys.len();
        let combined = format!("{}{}", self.master_key.to_hex(), index.to_string());
        match SecretKey::from_bytes(sha256(combined.into_bytes()).as_slice()) {
            Ok(derived_key) => {
                self.derived_keys.push(derived_key);
                Ok(derived_key)
            }
            Err(e) => Err(e),
        }
    }

    //save to file

    //load from file
}

#[cfg(test)]
mod test {
    //use super::*;
    use crypto::common::ByteArray;
    use keymanager::*;

    #[test]
    fn test_master_key_derivation() {
        println!("stage 1");

        let mut k = KeyManager::new();

        println!("Keychain: {:?}", k.master_key);

        println!("SHA256: {:?}", sha256(k.master_key.to_vec()));

        println!("derive1: {:?}", k.derive_key(0));
        println!("derive2: {:?}", k.derive_key(1));
        println!("derive1: {:?}", k.derive_key(0));

        println!("stage 2");

        assert_eq!(0, 1);
    }
}
