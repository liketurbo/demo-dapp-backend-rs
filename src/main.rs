use anyhow::anyhow;
use axum::{
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, RequestPartsExt, Router,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use base64::prelude::*;
use dotenv_codegen::dotenv;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::OnceCell;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fmt::Debug,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::timeout;
use tonlib::{
    address::TonAddress,
    client::TonClient,
    config::{MAINNET_CONFIG, TESTNET_CONFIG},
    contract::{TonContractFactory, TonContractInterface},
};

static JWT_KEYS: OnceCell<JwtKeys> = OnceCell::new();
static TTL: OnceCell<u64> = OnceCell::new();
static SHARED_SECRET: OnceCell<&[u8]> = OnceCell::new();
static DOMAIN: OnceCell<&str> = OnceCell::new();

struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl JwtKeys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

// Need for .unwrap() to work
impl Debug for JwtKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtKeys")
            .field("encoding", &"xxxxx".to_string())
            .field("decoding", &"xxxxx".to_string())
            .finish()
    }
}

#[tokio::main]
async fn main() {
    JWT_KEYS
        .set({
            let secret = dotenv!("SECRET");
            if secret.is_empty() {
                panic!("empty secret")
            }
            JwtKeys::new(secret.as_bytes())
        })
        .unwrap();
    TTL.set({
        let ttl = dotenv!("TTL");
        u64::from_str_radix(ttl, 10).expect("invalid TTL number")
    })
    .unwrap();
    SHARED_SECRET
        .set({
            let secret = dotenv!("SECRET");
            if secret.is_empty() {
                panic!("empty secret")
            }
            secret.as_bytes()
        })
        .unwrap();
    DOMAIN
        .set({
            let domain = dotenv!("DOMAIN");
            if domain.is_empty() {
                panic!("empty domain");
            }
            domain
        })
        .unwrap();

    // initialize tracing
    tracing_subscriber::fmt::init();

    let contract_factory = {
        TonClient::set_log_verbosity_level(0);
        let ton_client_mainnet = TonClient::builder()
            .with_pool_size(5)
            .with_config(MAINNET_CONFIG)
            .build()
            .await
            .unwrap();
        let ton_client_testnet = TonClient::builder()
            .with_pool_size(5)
            .with_config(TESTNET_CONFIG)
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

        Arc::new(ContractFactory {
            mainnet: ton_mainnet_contract_factory,
            testnet: ton_testnet_contract_factory,
        })
    };

    // build our application with a route
    let app = Router::new()
        .route("/generatePayload", post(generate_ton_proof_payload))
        .route("/checkProof", post(check_ton_proof))
        .route("/getAccountInfo", get(get_account_info))
        .with_state(contract_factory);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

struct ContractFactory {
    mainnet: TonContractFactory,
    testnet: TonContractFactory,
}

/// Generate ton_proof payload
///
/// ```
/// 0             8                 16               48
/// | random bits | expiration time | sha2 signature |
/// 0                                       32
/// |             payload_hex               |
/// ```
async fn generate_ton_proof_payload() -> Result<Json<GenerateTonProofPayload>, AppError> {
    let mut payload: [u8; 48] = [0; 48];
    let mut rng = rand::thread_rng();
    rng.fill(&mut payload[0..8]);

    if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {
        let expire = n.as_secs() + TTL.get().unwrap();
        let expire_be = expire.to_be_bytes();
        payload[8..16].copy_from_slice(&expire_be);
    } else {
        return Err(anyhow!("time went backwards 🤷").into());
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(SHARED_SECRET.get().unwrap())?;
    mac.update(&payload[0..16]);
    let signature = mac.finalize().into_bytes();
    payload[16..48].copy_from_slice(&signature);

    let hex = hex::encode(&payload[0..32]);

    Ok(Json(GenerateTonProofPayload { payload: hex }))
}

/// Check ton_proof
async fn check_ton_proof(
    State(contract_factory): State<Arc<ContractFactory>>,
    Json(body): Json<CheckProofPayload>,
) -> Result<Json<CheckTonProof>, AppError> {
    let data = hex::decode(body.proof.payload.clone())?;

    if data.len() != 32 {
        return Err(AppError::BadRequest(anyhow!(
            "invalid payload length, got {}, expected 32",
            data.len()
        )));
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(SHARED_SECRET.get().unwrap())?;
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
    if now > body.proof.timestamp + TTL.get().unwrap() {
        return Err(AppError::BadRequest(anyhow!("ton_proof has been expired")));
    }

    if body.proof.domain.value != *DOMAIN.get().unwrap() {
        return Err(AppError::BadRequest(anyhow!(
            "wrong domain, got {}, expected {}",
            body.proof.domain.value,
            *DOMAIN.get().unwrap()
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
        TonNetwork::Mainnet => &contract_factory.mainnet,
        TonNetwork::Testnet => &contract_factory.testnet,
    };

    let wallet_contract = contract_factory.get_contract(&addr);
    let res = timeout(
        Duration::from_secs(10),
        wallet_contract.run_get_method("get_public_key", &vec![]),
    ).await.map_err(|_| { 
        anyhow!("liteserver timeout")
    })??;

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
        exp: now + TTL.get().unwrap(),
        address: addr.to_base64_std(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &JWT_KEYS.get().unwrap().encoding,
    )?;

    Ok(Json(CheckTonProof { token }))
}

async fn get_account_info(claims: Claims) -> Result<Json<WalletAddress>, AppError> {
    Ok(Json(WalletAddress {
        address: claims.address,
    }))
}

enum AppError {
    BadRequest(anyhow::Error),
    ServerError(anyhow::Error),
    Unauthorized(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Self::BadRequest(e) => (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)),
            Self::ServerError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Something went wrong: {}", e),
            ),
            Self::Unauthorized(e) => (
                StatusCode::UNAUTHORIZED,
                format!("Authorization error: {}", e),
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

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize)]
struct WalletAddress {
    address: String,
}

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|e| AppError::Unauthorized(e.into()))?;

        // Decode the user data
        let token_data = decode::<Claims>(
            bearer.token(),
            &JWT_KEYS.get().unwrap().decoding,
            &Validation::default(),
        )
        .map_err(|e| AppError::Unauthorized(e.into()))?;

        let timestamp = token_data.claims.exp;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        if now >= timestamp {
            return Err(AppError::Unauthorized(anyhow!("token expired")));
        }

        Ok(token_data.claims)
    }
}
