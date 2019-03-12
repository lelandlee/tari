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

/// The Mnemonic system simplifies the encoding and decoding of a secret key into and from a Mnemonic word sequence
/// It can autodetect the language of the Mnemonic word sequence

use mnemonic_wordlists::*;
use common::*;
use std::slice::Iter;
use derive_error::Error;
use crypto::ristretto::RistrettoSecretKey as SecretKey;
use crypto::common::ByteArray;

#[derive(Debug, Error)]
pub enum MnemonicError {
    // The language was not set before conversion
    LanguageUndefined,
    // Only ChineseSimplified, ChineseTraditional, English, French, Italian, Japanese, Korean and Spanish are defined natural languages
    UnknownLanguage,
    // Only 2048 words for each language was selected to form Mnemonic word lists
    WordNotFound,
    // A mnemonic word does not exist for the requested index
    IndexOutOfBounds,
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
    /// Detects the mnemonic language of a specific word by searching all defined mnemonic word lists
    pub fn from(mnemonic_word: &str) -> Result<MnemonicLanguage, MnemonicError> {
        for language in MnemonicLanguage::iterator() {
            if find_mnemonic_index_from_word(mnemonic_word, &language).is_ok() {
                return Ok((*language).clone());
            }
        }
        return Err(MnemonicError::UnknownLanguage);
    }

    /// Returns an iterator for the MnemonicLanguage enum group to allow iteration over all defined languages
    pub fn iterator() -> Iter<'static, MnemonicLanguage> {
        static MNEMONIC_LANGUAGES: [MnemonicLanguage; 8] = [
            MnemonicLanguage::ChineseSimplified,
            MnemonicLanguage::ChineseTraditional,
            MnemonicLanguage::English,
            MnemonicLanguage::French,
            MnemonicLanguage::Italian,
            MnemonicLanguage::Japanese,
            MnemonicLanguage::Korean,
            MnemonicLanguage::Spanish,
        ];
        (MNEMONIC_LANGUAGES.into_iter())
    }
}

/// Finds and returns the index of a specific word in a mnemonic word list defined by the specified language
fn find_mnemonic_index_from_word(word: &str, language: &MnemonicLanguage) -> Result<usize, MnemonicError> {
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

/// Finds and returns the word for a specific index in a mnemonic word list defined by the specified language
fn find_mnemonic_word_from_index(index: usize, language: &MnemonicLanguage) -> Result<String, MnemonicError> {
    if index<MNEMONIC_ENGLISH_WORDS.len() {
        Ok(match language { //Select word according to specified language
            MnemonicLanguage::ChineseSimplified => MNEMONIC_CHINESE_SIMPLIFIED_WORDS[index],
            MnemonicLanguage::ChineseTraditional => MNEMONIC_CHINESE_TRADITIONAL_WORDS[index],
            MnemonicLanguage::English => MNEMONIC_ENGLISH_WORDS[index],
            MnemonicLanguage::French => MNEMONIC_FRENCH_WORDS[index],
            MnemonicLanguage::Italian => MNEMONIC_ITALIAN_WORDS[index],
            MnemonicLanguage::Japanese => MNEMONIC_JAPANESE_WORDS[index],
            MnemonicLanguage::Korean => MNEMONIC_KOREAN_WORDS[index],
            MnemonicLanguage::Spanish => MNEMONIC_SPANISH_WORDS[index],
        }.to_string())
    }
    else {
        Err(MnemonicError::IndexOutOfBounds)
    }
}

/// Converts a vector of bytes to a sequence of mnemonic words using the specified language
pub fn from_bytes(bytes: Vec<u8>, language: &MnemonicLanguage) -> Result<Vec<String>, MnemonicError> {
    let mut bits=bytes_to_bits(&bytes);

    //Pad with zeros if length not devisable by 11
    let group_bit_count=11;
    let padded_size=((bits.len() as f32/group_bit_count as f32).ceil()*group_bit_count as f32)as usize;
    bits.resize(padded_size,false);

    //Group each set of 11 bits to form one mnemonic word
    let mut mnemonic_sequence:Vec<String>=Vec::new();
    for i in 0..bits.len()/group_bit_count {
        let start_index=i*group_bit_count;
        let stop_index=start_index+group_bit_count;
        let sub_v=&bits[start_index..stop_index].to_vec();
        let word_index=bits_to_uint(sub_v);
        match find_mnemonic_word_from_index(word_index as usize,language) {
            Ok(mnemonic_word) => mnemonic_sequence.push(mnemonic_word),
            Err(err) => return Err(err),
        }
    };
    (Ok(mnemonic_sequence))
}

/// Generates a mnemonic sequence of words from the provided secret key
pub fn from_secretkey(k: &SecretKey, language: &MnemonicLanguage) -> Result<Vec<String>, MnemonicError> {
    (from_bytes(k.to_vec(),language))
}

/// Generates a mnemonic sequence of words from a vector of bytes, the language of the mnemonic sequence is autodetected
pub fn to_bytes(mnemonic_seq: &Vec<String>) -> Result<Vec<u8>, MnemonicError> {
    let language=MnemonicLanguage::from(&mnemonic_seq[0])?; //Autodetect language
    (to_bytes_with_language(mnemonic_seq, &language))
}

/// Generates a mnemonic sequence of words from a vector of bytes using the specified language
pub fn to_bytes_with_language(mnemonic_seq: &Vec<String>, language: &MnemonicLanguage) -> Result<Vec<u8>, MnemonicError> {
    let mut bits:Vec<bool>=Vec::new();
    for curr_word in mnemonic_seq {
        match find_mnemonic_index_from_word(&curr_word, &language) {
            Ok(index) => {
                let mut curr_bits=uint_to_bits(index,11);
                bits.extend(curr_bits.iter().map(|&i| i));
            },
            Err(err) => return Err(err),
        }
    }
    Ok(bits_to_bytes(&bits))
}

//TODO number of bits or words specify 12 or 24 mnemonic words

///
/*pub fn to_secretkey_with_language(mnemonic_seq: &Vec<String>, language: &MnemonicLanguage) -> Result<SecretKey, MnemonicError> {
    let bytes=to_bytes_with_language(mnemonic_seq,language)?;
    match SecretKey::from_bytes(&bytes) {
        Ok(k) => Ok(k),
        Err(e) => Err(e),
    }
}*/

/*
pub fn to_secretkey(mnemonic_seq: &Vec<String>) -> Result<SecretKey, MnemonicError> {
    let bytes=to_bytes_with_language(mnemonic_seq,language)?;
    match SecretKey::from_bytes(&bytes) {
        Ok(k) => Ok(k),
        Err(e) => Err(e),
    }
}
*/

#[cfg(test)]
mod test {
    use super::*;
    use mnemonic;




    #[test]
    fn test_mnemonic() {
        println!("stage 1");

        //let filename="bip0039_wordlists/english.txt";
        //let english_wordlists: Vec<String>=include_str!(filename.as_bytes()).split_whitespace().map(|s| s.into()).collect();
        //let english_wordlists: Vec<String>=include_str!("bip0039_wordlists/english.txt").split_whitespace().map(|s| s.into()).collect();
        //let english_wordlists=MnemonicManager::load_wordlist_file("bip0039_wordlists/english.txt");
        println!("english_wordlists = {:?}", MnemonicLanguage::from("abandon"));

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
        let bytes=SecretKey::random(&mut rng).to_vec();
        println!(" SecretKey bytes: {:?}",bytes);

        println!("        bytes: {:?}",bytes_to_bits(&bytes));

        let language=MnemonicLanguage::English;
        let mnemonic_seq_result= mnemonic::from_bytes(bytes, &language).unwrap();
        println!("      Mnemonic={:?}",mnemonic_seq_result);

        println!("      Bytes={:?}", SecretKey::from_bytes(mnemonic::to_bytes(&mnemonic_seq_result)));


        //Encode
        //Mnemonic::from_bytes(Vec<u8>,MnemonicLanguage::English)
        //Mnemonic::from_secretkey(SecretKey,MnemonicLanguage::English)

        //Decode
        //Mnemonic::to_bytes(Vec<String>) -> Vec<u8>
        //Mnemonic::to_secretkey(Vec<String>) ->SecretKey



        assert_eq!(0, 1);
    }
}
