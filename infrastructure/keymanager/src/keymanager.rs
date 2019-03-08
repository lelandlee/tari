// Copyright 2019 The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crypto::common::ByteArray;
use crypto::keys::SecretKeyFactory;
use crypto::ristretto::RistrettoSecretKey as SecretKey;
use rand;
use common::*;
use crypto::common::ByteArrayError;


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

    //TODO initialize master key from mnumonic key

    //TODO save to file

    //TODO load from file
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
