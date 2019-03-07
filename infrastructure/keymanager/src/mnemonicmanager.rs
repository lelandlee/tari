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

use mnemonic_wordlists::*;
use std::slice::Iter;
use derive_error::Error;

#[derive(Debug, Error)]
pub enum MnemonicError {
    // Only ChineseSimplified, ChineseTraditional, English, French, Italian, Japanese, Korean and Spanish are defined natural languages
    UnknownLanguage,
    // Only 2048 words for each language was selected to form Mnemonic word lists
    WordNotFound,
}

#[derive(Clone, Debug)]
pub enum MnemonicLanguage {
    ChineseSimplified,
    ChineseTraditional,
    English,
    French,
    Italian,
    Japanese,
    Korean,
    Spanish,
}

impl MnemonicLanguage {
    /// Returns an iterator for the MnemonicLanguage enum group to allow iteration over all defined languages
    pub fn iterator() -> Iter<'static, MnemonicLanguage> {
        static MNEMONIC_LANGUAGE: [MnemonicLanguage; 8] = [
            MnemonicLanguage::ChineseSimplified,
            MnemonicLanguage::ChineseTraditional,
            MnemonicLanguage::English,
            MnemonicLanguage::French,
            MnemonicLanguage::Italian,
            MnemonicLanguage::Japanese,
            MnemonicLanguage::Korean,
            MnemonicLanguage::Spanish,
        ];
        MNEMONIC_LANGUAGE.into_iter()
    }
}

/// Finds and returns the index of a specific word in a mnemonic word list defined by the specified language
pub fn find_mnemonic_word_index(word: &str, language: &MnemonicLanguage) -> Result<usize, MnemonicError> {
    let search_result:Result<usize, usize>;
    match language { //Search through languages are ordered according to the predominance (number of speakers in the world) of that language
        MnemonicLanguage::ChineseSimplified => search_result=MNEMONIC_CHINESE_SIMPLIFIED_WORDS.binary_search(&word),
        MnemonicLanguage::ChineseTraditional => search_result=MNEMONIC_CHINESE_TRADITIONAL_WORDS.binary_search(&word),
        MnemonicLanguage::English => search_result=MNEMONIC_ENGLISH_WORDS.binary_search(&word),
        MnemonicLanguage::French => search_result=MNEMONIC_FRENCH_WORDS.binary_search(&word),
        MnemonicLanguage::Italian => search_result=MNEMONIC_ITALIAN_WORDS.binary_search(&word),
        MnemonicLanguage::Japanese => search_result=MNEMONIC_JAPANESE_WORDS.binary_search(&word),
        MnemonicLanguage::Korean => search_result=MNEMONIC_KOREAN_WORDS.binary_search(&word),
        MnemonicLanguage::Spanish => search_result=MNEMONIC_SPANISH_WORDS.binary_search(&word),
    }
    match search_result {
        Ok(v) => Ok(v),
        Err(_err) => Err(MnemonicError::WordNotFound),
    }
}

/// Detects the mnemonic language of a specific word by searching all defined mnemonic word lists
pub fn find_language_of_mnemonic_word(word: &str) -> Result<MnemonicLanguage, MnemonicError> {
    for language in MnemonicLanguage::iterator() {
        if find_mnemonic_word_index(word, &language).is_ok() {
            return Ok((*language).clone());
        }
    }
    return Err(MnemonicError::UnknownLanguage);
}

/// The MnemonicManager simplifies the encoding and decoding of a a secret key into and from a Mnemonic word sequence
/// It can auto detect the language of the Mnemonic word sequence
pub struct MnemonicManager {
    pub language: Option<MnemonicLanguage>,
}

impl MnemonicManager {
    /// Construct a new MnemonicManager when the mnemonic language is unknown
    pub fn new() -> MnemonicManager {
        MnemonicManager { language: None }
    }

    /// Creates a new MnemonicManager when the mnemonic language is known
    pub fn from(language: MnemonicLanguage) -> MnemonicManager {
        MnemonicManager { language: Some(language) }
    }

    /// Finds the index of a specific word in a mnemonic word list. The correct word list is either defined or detected.
    pub fn find(&mut self, word: &str) -> Result<usize, MnemonicError> {
        if self.language.is_none() { //Language not defined, then autodetect language
            self.set_language_from_word(word)?;
        }
        match &self.language {
            Some(language) => find_mnemonic_word_index(word, language),
            None => Err(MnemonicError::UnknownLanguage),
        }
    }

    /// Finds the corresponding mnemonic word list that contains the specified word and uses the detected language to set the language of the MnemonicManager
    pub fn set_language_from_word(&mut self, word: &str) -> Result<MnemonicLanguage, MnemonicError> {
        match find_language_of_mnemonic_word(word) {
            Ok(detected_language) => {
                self.language=Some(detected_language.clone());
                Ok(detected_language)
            },
            Err(err) => Err(err),
        }
    }

    //TODO convert Secret key to Mnemonic word sequence
}


/*pub fn byte_to_bits (b:u8) -> Vec<bool> {


}*/



#[cfg(test)]
mod test {
    use super::*;
    //use crypto::common::ByteArray;
    use mnemonicmanager::*;

    #[test]
    fn test_mnemonic() {
        println!("stage 1");

        //let filename="bip0039_wordlists/english.txt";
        //let english_wordlists: Vec<String>=include_str!(filename.as_bytes()).split_whitespace().map(|s| s.into()).collect();
        //let english_wordlists: Vec<String>=include_str!("bip0039_wordlists/english.txt").split_whitespace().map(|s| s.into()).collect();
        //let english_wordlists=MnemonicManager::load_wordlist_file("bip0039_wordlists/english.txt");
        println!("english_wordlists = {:?}", find_language_of_mnemonic_word("abandon"));

        /*
        //find word position
        let find_word="abandon".to_string();
        match english_wordlists.binary_search(&find_word) {
            Ok(word_index) => println!(" word = {:?}",english_wordlists[word_index]),
            Err(_) => println!(" not found "),
        }*/

        use rand;
        use crypto::ristretto::RistrettoSecretKey as SecretKey;
        use crypto::keys::SecretKeyFactory;
        use crypto::ristretto::ristretto_keys;
        use crypto::common::ByteArray;

        let mut rng = rand::OsRng::new().unwrap();
        let s=SecretKey::random(&mut rng).to_vec();

        let mut b:u8=254;
        let mut bits = Vec::new();
        for _i in (0..7).rev() {
            bits.push(b%2);
            b=b/2;
        }
        println!("      bits={:?}",bits);




        println!(" SecretKey: {:?}",s);










        assert_eq!(0, 1);
    }
}
