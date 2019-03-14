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

use sha2::{Digest, Sha256};

pub fn sha256(input_vec: Vec<u8>) -> Vec<u8> {
    let mut h = Sha256::new();
    h.input(input_vec);
    (h.result().to_vec())
}

/// Converts a single input integer to a vector of bits
pub fn uint_to_bits(value: usize, bit_count: usize) -> Vec<bool> {
    let mut bits: Vec<bool> = Vec::new();
    let mut v = value;
    for _i in 0..bit_count {
        bits.push(v % 2 > 0);
        v = v / 2;
    }
    bits.reverse();
    (bits)
}

/// Converts a vector of input bits to its integer representation
pub fn bits_to_uint(bits: &Vec<bool>) -> usize {
    let mut value: usize = 0;
    for i in 0..bits.len() {
        value += (bits[i] as usize) * (2 as usize).pow((bits.len() - i - 1) as u32);
    }
    (value)
}

/// Converts a vector of input bytes to a vector of bits
pub fn bytes_to_bits(bytes: &Vec<u8>) -> Vec<bool> {
    let mut bits: Vec<bool> = Vec::new();
    for curr_byte in bytes.iter() {
        let curr_bits = uint_to_bits(*curr_byte as usize, 8);
        bits.extend(curr_bits.iter().map(|&i| i));
    }
    (bits)
}

/// Converts a vector of bits to a vector of bytes
pub fn bits_to_bytes(bits: &Vec<bool>) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    let group_bit_count = 8;
    for i in 0..bits.len() / group_bit_count {
        let start_index = i * group_bit_count;
        let stop_index = start_index + group_bit_count;
        bytes.push(bits_to_uint(&bits[start_index..stop_index].to_vec()) as u8);
    }
    (bytes)
}
