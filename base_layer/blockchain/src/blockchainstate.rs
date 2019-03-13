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

// This file is used to store the current blockchain state


/// The BlockchainState struct keeps record of the current UTXO, total kernels and headers.
use merklemountainrange::mmr::*;
use tari_core::transaction::{TransactionKernel, TransactionOutput};
use tari_core::block::Block;
use tari_core::blockheader::BlockHeader;
use tari_core::types::Hasher;


pub struct BlockchainState {
    _outputs: MerkleMountainRange<TransactionOutput, Hasher>,
    _kernals: MerkleMountainRange<TransactionKernel, Hasher>,
    _headers: MerkleMountainRange<BlockHeader, Hasher>,
}

impl BlockchainState {
    /// This function creates a new blockchainstate, this will keep track of the current state of the blockchain.
    pub fn new() -> BlockchainState {
        BlockchainState { _outputs: MerkleMountainRange::new(), _kernals: MerkleMountainRange::new(), _headers::MerkleMountainRange::new(), }
    }

/// This function consumes a new block
/// The if it returns OK(), the block was accepted and proccessed, else it returns an error why the block was rejected
    pub fn add_block(new_block : Block) -> Result<_,BlockProrror>
}
