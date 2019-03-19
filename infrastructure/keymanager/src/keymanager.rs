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

use crate::{common::*, mnemonic::*};
use crypto::{
    common::{ByteArray, ByteArrayError},
    keys::SecretKeyFactory,
    ristretto::RistrettoSecretKey as SecretKey,
};
use derive_error::Error;
// use rand;
use rand::{CryptoRng, Rng};
use serde_derive::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{prelude::*, ErrorKind},
};

#[derive(Debug, Error)]
pub enum KeyManagerError {
    // Could not convert into byte array
    ByteArrayError(ByteArrayError),
    // Could not convert provided Mnemonic into master key
    MnemonicError(MnemonicError),
    // The specified backup file could not be opened
    FileOpen,
    // Could not read from backup file
    FileRead,
    // Problem deserializing JSON into a new KeyManager
    Deserialize,
}

#[derive(Clone, Debug)]
pub struct DerivedKey {
    pub k: SecretKey,
    pub key_index: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyManager {
    pub master_key: SecretKey,
    pub branch_seed: String,
    pub primary_key_index: usize,
}

impl KeyManager {
    /// Creates a new KeyManager with a new randomly selected master_key
    pub fn new<R: CryptoRng + Rng>(rng: &mut R) -> KeyManager {
        KeyManager { master_key: SecretKey::random(rng), branch_seed: "".to_string(), primary_key_index: 0 }
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
    ) -> Result<KeyManager, KeyManagerError>
    {
        match SecretKey::from_bytes(sha256(seed_phrase.into_bytes()).as_slice()) {
            Ok(master_key) => Ok(KeyManager { master_key, branch_seed, primary_key_index }),
            Err(e) => Err(KeyManagerError::from(e)),
        }
    }

    /// Creates a KeyManager from the provided sequence of mnemonic words, the language of the mnemonic sequence will be
    /// auto detected
    pub fn from_mnemonic(
        mnemonic_seq: &Vec<String>,
        branch_seed: String,
        primary_key_index: usize,
    ) -> Result<KeyManager, KeyManagerError>
    {
        match SecretKey::from_mnemonic(mnemonic_seq) {
            Ok(master_key) => Ok(KeyManager { master_key, branch_seed, primary_key_index }),
            Err(e) => Err(KeyManagerError::from(e)),
        }
    }

    // TODO: file should be decrypted using Salsa20 or ChaCha20
    /// Load KeyManager state from backup file
    pub fn from_file(filename: &String) -> Result<KeyManager, KeyManagerError> {
        let mut file_handle = match File::open(&filename) {
            Ok(file) => file,
            Err(_e) => return Err(KeyManagerError::FileOpen),
        };
        let mut file_content = String::new();
        match file_handle.read_to_string(&mut file_content) {
            Ok(_) => match serde_json::from_str(&file_content) {
                Ok(km) => Ok(km),
                Err(_) => Err(KeyManagerError::Deserialize),
            },
            Err(_) => Err(KeyManagerError::FileRead),
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

    // TODO: file should be encrypted using Salsa20 or ChaCha20
    // TODO: to_file can made into a reusable trait for other structs
    /// Backup KeyManager state in file specified by filename
    pub fn to_file(&self, filename: &String) -> std::io::Result<()> {
        let mut file_handle = File::create(filename)?;
        match serde_json::to_string(&self) {
            Ok(json_data) => {
                file_handle.write_all(json_data.as_bytes())?;
                Ok(())
            },
            Err(_) => Err(std::io::Error::new(ErrorKind::Other, "JSON parse error")),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::keymanager::*;
    use std::fs::remove_file;

    #[test]
    fn test_new_keymanager() {
        let mut rng = rand::OsRng::new().unwrap();
        let km1 = KeyManager::new(&mut rng);
        let km2 = KeyManager::new(&mut rng);
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
        let mut rng = rand::OsRng::new().unwrap();
        let mut km = KeyManager::new(&mut rng);
        let next_key1_result = km.next_key();
        let next_key2_result = km.next_key();
        let desired_key_index1 = 1;
        let desired_key_index2 = 2;
        let derived_key1_result = km.derive_key(desired_key_index1);
        let derived_key2_result = km.derive_key(desired_key_index2);
        if next_key1_result.is_ok() &&
            next_key2_result.is_ok() &&
            derived_key1_result.is_ok() &&
            derived_key2_result.is_ok()
        {
            let next_key1 = next_key1_result.unwrap();
            let next_key2 = next_key2_result.unwrap();
            let derived_key1 = derived_key1_result.unwrap();
            let derived_key2 = derived_key2_result.unwrap();
            assert_ne!(next_key1.k, next_key2.k);
            assert_eq!(next_key1.k, derived_key1.k);
            assert_eq!(next_key2.k, derived_key2.k);
            assert_eq!(next_key1.key_index, desired_key_index1);
            assert_eq!(next_key2.key_index, desired_key_index2);
        }
    }

    #[test]
    fn test_to_file_and_from_file() {
        let mut rng = rand::OsRng::new().unwrap();
        let desired_km = KeyManager::new(&mut rng);
        let backup_filename = "test_km_backup.json".to_string();
        // Backup KeyManager to file
        match desired_km.to_file(&backup_filename) {
            Ok(_v) => {
                // Restore KeyManager from file
                match KeyManager::from_file(&backup_filename) {
                    Ok(backup_km) => {
                        // Remove temp keymanager backup file
                        remove_file(backup_filename).unwrap();

                        assert_eq!(desired_km, backup_km);
                    },
                    Err(_e) => assert!(false),
                };
            },
            Err(_e) => assert!(false),
        };
    }
}
