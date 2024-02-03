use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct GenerateTonProofPayload {
    pub payload: String,
}

/// ```
/// {
///   "address": "0:f63660ff947e5fe6ed4a8f729f1b24ef859497d0483aaa9d9ae48414297c4e1b", // user's address
///   "network": "-239", // "-239" for mainnet and "-1" for testnet
///   "proof": {
///     "timestamp": 1668094767, // unix epoch seconds
///     "domain": {
///       "lengthBytes": 21,
///       "value": "ton-connect.github.io"
///     },
///     "signature": "28tWSg8RDB3P/iIYupySINq1o3F5xLodndzNFHOtdi16Z+MuII8LAPnHLT3E6WTB27//qY4psU5Rf5/aJaIIAA==",
///     "payload": "E5B4ARS6CdOI2b5e1jz0jnS-x-a3DgfNXprrg_3pec0=" // payload from the step 1.
///   }
/// }
/// ```
#[derive(Deserialize)]
pub struct CheckProofPayload {
    pub address: String,
    pub network: TonNetwork,
    pub proof: TonProof,
}

#[derive(Deserialize)]
pub enum TonNetwork {
    #[serde(rename = "-239")]
    Mainnet,
    #[serde(rename = "-3")]
    Testnet,
}

#[derive(Deserialize)]
pub struct TonProof {
    pub domain: TonDomain,
    pub payload: String,
    pub signature: String,
    pub state_init: String,
    pub timestamp: u64,
}

#[derive(Deserialize)]
pub struct TonDomain {
    #[serde(rename = "lengthBytes")]
    pub length_bytes: u64,
    pub value: String,
}

#[derive(Serialize)]
pub struct CheckTonProof {
    pub token: String,
}

#[derive(Serialize)]
pub struct WalletAddress {
    pub address: String,
}
