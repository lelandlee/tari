use mnemonic_wordlists::*;
use std::slice::Iter;

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

pub fn find_mnemonic_word_index(word: &str, language: &MnemonicLanguage) -> Result<usize, usize> {
    match language {
        MnemonicLanguage::ChineseSimplified => MNEMONIC_CHINESE_SIMPLIFIED_WORDS.binary_search(&word),
        MnemonicLanguage::ChineseTraditional => MNEMONIC_CHINESE_TRADITIONAL_WORDS.binary_search(&word),
        MnemonicLanguage::English => MNEMONIC_ENGLISH_WORDS.binary_search(&word),
        MnemonicLanguage::French => MNEMONIC_FRENCH_WORDS.binary_search(&word),
        MnemonicLanguage::Italian => MNEMONIC_ITALIAN_WORDS.binary_search(&word),
        MnemonicLanguage::Japanese => MNEMONIC_JAPANESE_WORDS.binary_search(&word),
        MnemonicLanguage::Korean => MNEMONIC_KOREAN_WORDS.binary_search(&word),
        MnemonicLanguage::Spanish => MNEMONIC_SPANISH_WORDS.binary_search(&word),
    }
}

//Languages are ordered according to number of speakers in the world
pub fn find_language_of_mnemonic_word(word: &str) -> Result<MnemonicLanguage, usize> {
    for language in MnemonicLanguage::iterator() {
        if find_mnemonic_word_index(word, &language).is_ok() {
            return Ok((*language).clone());
        }
    }
    return Err(0);
}

pub struct MnemonicManager {
    pub language: Option<MnemonicLanguage>,
}

impl MnemonicManager {
    pub fn new() -> MnemonicManager {
        MnemonicManager { language: None }
    }

    pub fn from(language: MnemonicLanguage) -> MnemonicManager {
        MnemonicManager { language: Some(language) }
    }

    pub fn find_word(&mut self, word: &str) -> Result<usize, usize> {
        if self.language.is_none() {
            //Language not defined, then autodetect language
            let lang_search_result = find_language_of_mnemonic_word(word);
            if lang_search_result.is_ok() {
                self.language = Some(lang_search_result.unwrap());
            }
        }
        match &self.language {
            Some(language) => find_mnemonic_word_index(word, language),
            None => Err(0), //TODO need proper error
        }
    }

    //TODO  Secret key to Mnemonic word sequence
}

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

        assert_eq!(0, 1);
    }
}
