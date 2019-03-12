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

// A new derived key for a specific index can be generated as derived_key=SHA256(master_key||branch_seed||index)

use crypto::common::ByteArray;
use crypto::keys::SecretKeyFactory;
use crypto::ristretto::RistrettoSecretKey as SecretKey;
use rand;
use common::*;
use crypto::common::ByteArrayError;

pub struct DerivedKey {
    pub k: SecretKey,
    pub key_index:usize,
}


pub struct KeyManager {
    pub master_key: SecretKey,
    pub branch_seed: String,
    pub primary_key_index:usize,
}

impl KeyManager {
    pub fn new() -> KeyManager {
        let mut rng = rand::OsRng::new().unwrap();
        KeyManager { master_key: SecretKey::random(&mut rng),branch_seed:"".to_string(), primary_key_index: 0 }
    }

    pub fn from(master_key: SecretKey,branch_seed: String,primary_key_index: usize) -> KeyManager {
        KeyManager { master_key,branch_seed, primary_key_index }
    }

    /*pub fn from_seed(seed: String) -> KeyManager {
        KeyManager {
            master_key: SecretKey::from_bytes(sha256(seed.into_bytes()).as_slice()).unwrap(),
            primary_key_index:0,
        }
    }*/


    //TODO initialize master key from mnemonic key
    pub fn from_mnemonic(mnemonic_seq: &Vec<String>) -> KeyManager {

    }

    // Derived keys are generated as derived_key=SHA256(master_key||branch_seed||index)
    pub fn derive_key(&self, key_index: usize) -> Result<DerivedKey, ByteArrayError> {
        let concatenated = format!("{}{}", self.master_key.to_hex(), key_index.to_string());
        match SecretKey::from_bytes(sha256(concatenated.into_bytes()).as_slice()) {
            Ok(k) => Ok(DerivedKey { k, key_index}),
            Err(err) => Err(err),
        }
    }

    pub fn next_key(&mut self) -> Result<DerivedKey, ByteArrayError> {
        self.primary_key_index+=1;
        (self.derive_key(self.primary_key_index))
    }



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
