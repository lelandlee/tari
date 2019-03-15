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

use common::*;
use crypto::common::ByteArray;
use crypto::common::ByteArrayError;
use crypto::keys::SecretKeyFactory;
use crypto::ristretto::RistrettoSecretKey as SecretKey;
use derive_error::Error;
use mnemonic::*;
use rand;


use std::fs::File;
use std::io::prelude::*;

//use serde::{Serialize, Deserialize};
//use serde::ser::{Serialize, SerializeStruct, Serializer};
//use serde::de::{Deserialize, Deserializer, Visitor, SeqAccess, MapAccess};

#[derive(Debug, Error)]
pub enum KeyManagerError {
    // Could not convert into byte array
    ByteArrayError,
    // Could not convert provided Mnemonic into master key
    DecodeMnemonic,
}

impl From<ByteArrayError> for KeyManagerError {
    /// Converts from ByteArrayError to KeyManagerError
    fn from(_e: ByteArrayError) -> Self {
        KeyManagerError::ByteArrayError
    }
}

impl From<MnemonicError> for KeyManagerError {
    /// Converts from MnemonicError to KeyManagerError
    fn from(_e: MnemonicError) -> Self {
        KeyManagerError::DecodeMnemonic
    }
}

#[derive(Clone, Debug)]
pub struct DerivedKey {
    pub k: SecretKey,
    pub key_index: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct KeyManager {
    pub master_key: SecretKey,
    pub branch_seed: String,
    pub primary_key_index: usize,
}
/*
impl Serialize for KeyManager {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut state = serializer.serialize_struct("KeyManager", 3)?;
        state.serialize_field("master_key", &self.master_key.to_hex())?;
        state.serialize_field("branch_seed", &self.branch_seed)?;
        state.serialize_field("primary_key_index", &self.primary_key_index)?;
        state.end()
    }
}

impl Deserialize for KeyManager  {
   fn deserialize<D>(deserializer: D) -> Result<KeyManager, D::Error>
        where
            D: Deserializer<'de>,
    {

        deserializer.visit(TimeVisitor)
        //deserializer.deserialize_string()(I32Visitor)
    }
}


struct KeyVisitor;

impl Visitor for KeyVisitor {
    type Value = MyTime;

    fn visit_string<E>(&mut self, str_data: String) -> Result<MyTime, E>
        where E: serde::de::Error,
    {
        // Vamos con un strptime() con nuestro formato y vemos que paso
        match time::strptime(&str_data, "%d/%m/%Y %X%z")
            {
                // Todo ok, convertimos al Timespec
                Ok(parsed_time) => Ok(MyTime::new(parsed_time.to_timespec())),

                // Hubo un problema, formatearlo y pasarlo a serde
                Err(parse_error) => Err(serde::de::Error::syntax(&format!(
                    "time parser error: {}", parse_error)))
            }
    }
}*/




impl KeyManager {
    /// Creates a new KeyManager with a new randomly selected master_key
    pub fn new() -> KeyManager {
        let mut rng = rand::OsRng::new().unwrap();
        KeyManager { master_key: SecretKey::random(&mut rng), branch_seed: "".to_string(), primary_key_index: 0 }
    }

    /// Constructs a KeyManager from known parts
    pub fn from(master_key: SecretKey, branch_seed: String, primary_key_index: usize) -> KeyManager {
        KeyManager { master_key, branch_seed, primary_key_index }
    }

    /// Constructs a KeyManager by generating a master_key=SHA256(seed_phrase) using a non-mnemonic seed phrase
    pub fn from_seed_phrase(
        seed_phrase: String,
        branch_seed: String,
        primary_key_index: usize,
    ) -> Result<KeyManager, KeyManagerError> {
        match SecretKey::from_bytes(sha256(seed_phrase.into_bytes()).as_slice()) {
            Ok(master_key) => Ok(KeyManager { master_key, branch_seed, primary_key_index }),
            Err(e) => Err(KeyManagerError::from(e)),
        }
    }

    /// Creates a KeyManager from the provided sequence of mnemonic words, the language of the mnemonic sequence will be auto detected
    pub fn from_mnemonic(
        mnemonic_seq: &Vec<String>,
        branch_seed: String,
        primary_key_index: usize,
    ) -> Result<KeyManager, KeyManagerError> {
        match SecretKey::from_mnemonic(mnemonic_seq) {
            Ok(master_key) => Ok(KeyManager { master_key, branch_seed, primary_key_index }),
            Err(e) => Err(KeyManagerError::from(e)),
        }
    }

    /// Derive a new private key from master key: derived_key=SHA256(master_key||branch_seed||index)
    pub fn derive_key(&self, key_index: usize) -> Result<DerivedKey, ByteArrayError> {
        let concatenated = format!("{}{}", self.master_key.to_hex(), key_index.to_string());
        match SecretKey::from_bytes(sha256(concatenated.into_bytes()).as_slice()) {
            Ok(k) => Ok(DerivedKey { k, key_index }),
            Err(e) => Err(e),
        }
    }

    /// Generate next deterministic private key derived from master key
    pub fn next_key(&mut self) -> Result<DerivedKey, ByteArrayError> {
        self.primary_key_index += 1;
        (self.derive_key(self.primary_key_index))
    }



    //TODO save to file
    //TODO change into EncryptedFile trait
    pub fn save_file(&self, filename: String) -> std::io::Result<()> {


        let mut file = File::create(filename)?;


        let json_data = serde_json::to_string_pretty(&self).unwrap();
        println!("{}",json_data);




        file.write_all(json_data.as_bytes())?;

        Ok(())
    }

    //TODO load from file
}

#[cfg(test)]
mod test {
    use keymanager::*;

    #[test]
    fn test_new_keymanager() {
        let km1 = KeyManager::new();
        let km2 = KeyManager::new();
        assert_ne!(km1.master_key, km2.master_key);
    }

    #[test]
    fn test_from_seed_phrase() {
        let seed_phrase1 = "random seed phrase".to_string();
        let seed_phrase2 = "additional random Seed phrase".to_string();
        let branch_seed = "".to_string();
        let km1 = KeyManager::from_seed_phrase(seed_phrase1, branch_seed.clone(), 0);
        let km2 = KeyManager::from_seed_phrase(seed_phrase2, branch_seed, 0);
        if km1.is_ok() && km2.is_ok() {
            assert_ne!(km1.unwrap().master_key, km2.unwrap().master_key);
        } else {
            assert!(false)
        }
    }

    #[test]
    fn test_from_mnemonic() {
        let mnemonic_seq1 = vec![
            "clever", "jaguar", "bus", "engage", "oil", "august", "media", "high", "trick", "remove", "tiny", "join",
            "item", "tobacco", "orange", "pony", "tomorrow", "also", "dignity", "giraffe", "little", "board", "army",
            "scale",
        ]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
        let mnemonic_seq2 = vec![
            "spatial", "travel", "remove", "few", "cinnamon", "three", "drift", "grit", "amazing", "isolate", "merge",
            "tonight", "apple", "garden", "damage", "job", "equal", "ahead", "wolf", "initial", "woman", "regret",
            "neither", "divorce",
        ]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
        let branch_seed = "".to_string();
        let km1 = KeyManager::from_mnemonic(&mnemonic_seq1, branch_seed.clone(), 0);
        let km2 = KeyManager::from_mnemonic(&mnemonic_seq2, branch_seed, 0);

        if km1.is_ok() && km2.is_ok() {
            assert_ne!(km1.unwrap().master_key, km2.unwrap().master_key);
        } else {
            assert!(false)
        }
    }

    #[test]
    fn test_derive_and_next_key() {
        let mut km = KeyManager::new();
        let next_key1_result = km.next_key();
        let next_key2_result = km.next_key();
        let desired_key_index1 = 1;
        let desired_key_index2 = 2;
        let derived_key1_result = km.derive_key(desired_key_index1);
        let derived_key2_result = km.derive_key(desired_key_index2);
        if next_key1_result.is_ok() && next_key2_result.is_ok() && derived_key1_result.is_ok() && derived_key2_result.is_ok() {
            let next_key1=next_key1_result.unwrap();
            let next_key2=next_key2_result.unwrap();
            let derived_key1=derived_key1_result.unwrap();
            let derived_key2=derived_key2_result.unwrap();
            assert_ne!(next_key1.k, next_key2.k);
            assert_eq!(next_key1.k, derived_key1.k);
            assert_eq!(next_key2.k, derived_key2.k);
            assert_eq!(next_key1.key_index, desired_key_index1);
            assert_eq!(next_key2.key_index, desired_key_index2);
        }
    }

    #[test]
    fn test_save_file() {

        let km =KeyManager::new();

        km.save_file("test.txt".to_string());


        assert!(false);
    }
}
