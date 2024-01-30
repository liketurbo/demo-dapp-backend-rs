use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::anyhow;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::prelude::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tonlib::{
    address::TonAddress,
    client::TonClient,
    contract::{TonContractFactory, TonContractInterface},
};

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    const MAINNET_NETWORK: &'static str = "-239";
    const TESTNET_NETWORK: &'static str = "-3";

    TonClient::set_log_verbosity_level(0);
    let ton_client_mainnet = TonClient::builder()
        .with_pool_size(5)
        .with_config(MAINNET_NETWORK)
        .build()
        .await
        .unwrap();
    let ton_client_testnet = TonClient::builder()
        .with_pool_size(5)
        .with_config(TESTNET_NETWORK)
        .build()
        .await
        .unwrap();
    let ton_mainnet_contract_factory = TonContractFactory::builder(&ton_client_mainnet)
        .build()
        .await
        .unwrap();
    let ton_testnet_contract_factory = TonContractFactory::builder(&ton_client_testnet)
        .build()
        .await
        .unwrap();

    let shared_state = Arc::new(AppState {
        secret,
        ttl: 3600, // 1 hour
        domain: "example.com".to_string(),
        ton_mainnet_contract_factory,
        ton_testnet_contract_factory,
    });

    // build our application with a route
    let app = Router::new()
        .route("/generatePayload", post(generate_ton_proof_payload))
        .route("/checkProof", post(check_ton_proof))
        .with_state(shared_state);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Generate ton_proof payload
///
/// ```
/// 0             8                 16               48
/// | random bits | expiration time | sha2 signature |
/// 0                                       32
/// |             payload_hex               |
/// ```
async fn generate_ton_proof_payload(
    State(state): State<Arc<AppState>>,
) -> Result<Json<GenerateTonProofPayload>, AppError> {
    let mut payload: [u8; 48] = [0; 48];
    let mut rng = rand::thread_rng();
    rng.fill(&mut payload[0..8]);

    if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {
        let expire = n.as_secs() + state.ttl;
        let expire_be = expire.to_be_bytes();
        payload[8..16].copy_from_slice(&expire_be);
    } else {
        return Err(anyhow!("time went backwards 🤷").into());
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(state.secret.as_bytes())?;
    mac.update(&payload[0..16]);
    let signature = mac.finalize().into_bytes();
    payload[16..48].copy_from_slice(&signature);

    let hex = hex::encode(&payload[0..32]);

    Ok(Json(GenerateTonProofPayload { payload: hex }))
}

/// Check ton_proof
async fn check_ton_proof(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CheckProofPayload>,
) -> Result<Json<CheckTonProof>, AppError> {
    let data = hex::decode(body.proof.payload.clone())?;

    if data.len() != 32 {
        return Err(AppError::BadRequest(anyhow!(
            "invalid payload length, got {}, expected 32",
            data.len()
        )));
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(state.secret.as_bytes())?;
    mac.update(&data[..16]);
    let signature_bytes: [u8; 32] = mac.finalize().into_bytes().into();
    let signature_valid = data
        .iter()
        .skip(16)
        .zip(signature_bytes.iter().take(16))
        .all(|(a, b)| a == b);

    if signature_valid {
        return Err(AppError::BadRequest(anyhow!("invalid payload signature")));
    }

    let expire_b: [u8; 8] = data[8..16].try_into().expect("already checked length");
    let expire_d = u64::from_be_bytes(expire_b);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // check payload expiration
    if now > expire_d {
        return Err(AppError::BadRequest(anyhow!("payload expired")));
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // check ton_proof expiration
    if now > body.proof.timestamp + state.ttl {
        return Err(AppError::BadRequest(anyhow!("ton_proof has been expired")));
    }

    if body.proof.domain.value != state.domain {
        return Err(AppError::BadRequest(anyhow!(
            "wrong domain, got {}, expected {}",
            body.proof.domain.value,
            state.domain
        )));
    }

    if body.proof.domain.length_bytes != body.proof.domain.value.len() as u64 {
        return Err(AppError::BadRequest(anyhow!(
            "domain length mismatched against provided length_bytes of {}",
            body.proof.domain.length_bytes
        )));
    }

    const TON_PROOF_PREFIX: &'static str = "ton-proof-item-v2/";

    let addr =
        TonAddress::from_hex_str(&body.address).map_err(|e| AppError::BadRequest(e.into()))?;

    let mut msg: Vec<u8> = Vec::new();
    msg.extend_from_slice(TON_PROOF_PREFIX.as_bytes());
    msg.extend_from_slice(&addr.workchain.to_be_bytes());
    msg.extend_from_slice(&addr.hash_part); // should it be big endian?
    msg.extend_from_slice(&(body.proof.domain.length_bytes as u32).to_le_bytes());
    msg.extend_from_slice(body.proof.domain.value.as_bytes());
    msg.extend_from_slice(&body.proof.timestamp.to_le_bytes());
    msg.extend_from_slice(body.proof.payload.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(msg);
    let msg_hash = hasher.finalize();

    const TON_CONNECT_PREFIX: &'static str = "ton-connect";

    let mut full_msg: Vec<u8> = vec![0xff, 0xff];
    full_msg.extend_from_slice(TON_CONNECT_PREFIX.as_bytes());
    full_msg.extend_from_slice(&msg_hash);

    let mut hasher = Sha256::new();
    hasher.update(full_msg);
    let full_msg_hash = hasher.finalize();

    let contract_factory = match body.network {
        TonNetwork::Mainnet => &state.ton_mainnet_contract_factory,
        TonNetwork::Testnet => &state.ton_testnet_contract_factory,
    };

    let wallet_contract = contract_factory.get_contract(&addr);
    let res = wallet_contract
        .run_get_method("get_public_key", &vec![])
        .await?;
    let pubkey_n = res.stack.get_biguint(0)?;
    let pubkey_bytes: [u8; 32] = pubkey_n
        .to_bytes_be()
        .try_into()
        .map_err(|_| anyhow!("failed to extract 32 bits long public from the wallet contract"))?;
    let pubkey = VerifyingKey::from_bytes(&pubkey_bytes)?;
    let signature_bytes: [u8; 64] = BASE64_STANDARD
        .decode(&body.proof.signature)
        .map_err(|e| AppError::BadRequest(e.into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest(anyhow!("expected 64 bit long signature")))?;
    let signature = Signature::from_bytes(&signature_bytes);
    pubkey
        .verify(&full_msg_hash, &signature)
        .map_err(|e| AppError::BadRequest(e.into()))?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = Claims {
        exp: now + state.ttl,
        address: addr.to_base64_std(),
    };

    use jsonwebtoken::{encode, EncodingKey, Header};

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.secret.as_bytes()),
    )?;

    Ok(Json(CheckTonProof { token }))
}

struct AppState {
    secret: String,
    ttl: u64,
    domain: String,
    ton_mainnet_contract_factory: TonContractFactory,
    ton_testnet_contract_factory: TonContractFactory,
}

enum AppError {
    BadRequest(anyhow::Error),
    ServerError(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Self::BadRequest(e) => (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)),
            Self::ServerError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Something went wrong: {}", e),
            ),
        };

        let body = Json(json!({
            "error": error_message
        }));

        (status, body).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self::ServerError(err.into())
    }
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
struct CheckProofPayload {
    address: String,
    network: TonNetwork,
    proof: TonProof,
}

#[derive(Deserialize)]
enum TonNetwork {
    #[serde(rename = "-239")]
    Mainnet,
    #[serde(rename = "-3")]
    Testnet,
}

#[derive(Deserialize)]
struct TonProof {
    domain: TonDomain,
    payload: String,
    signature: String,
    state_init: String,
    timestamp: u64,
}

#[derive(Deserialize)]
struct TonDomain {
    #[serde(rename = "lengthBytes")]
    length_bytes: u64,
    value: String,
}

#[derive(Serialize)]
struct Claims {
    exp: u64,
    address: String,
}

#[derive(Serialize)]
struct CheckTonProof {
    token: String,
}

#[derive(Serialize)]
struct GenerateTonProofPayload {
    payload: String,
}
