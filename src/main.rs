use crate::{
    dto::{CheckTonProof, TonNetwork},
    error::{anyhow, AppError},
};
use async_trait::async_trait;
use axum::{
    extract::{FromRequest, FromRequestParts, Request, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        request::Parts,
        HeaderValue, Method,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, RequestExt, RequestPartsExt, Router,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use base64::prelude::*;
use dotenv_codegen::dotenv;
use dto::{CheckProofPayload, GenerateTonProofPayload, WalletAddress};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::OnceCell;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
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
use tower_http::cors::CorsLayer;

mod dto;
mod error;

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
        .route(
            "/ton-proof/generatePayload",
            post(generate_ton_proof_payload),
        )
        .route("/ton-proof/checkProof", post(check_ton_proof))
        .route("/dapp/getAccountInfo", get(get_account_info))
        .layer(
            // see https://docs.rs/tower-http/latest/tower_http/cors/index.html
            // for more details
            //
            // pay attention that for some request types like posting content-type: application/json
            // it is required to add ".allow_headers([http::header::CONTENT_TYPE])"
            // or see this issue https://github.com/tokio-rs/axum/issues/849
            CorsLayer::new()
                .allow_origin("http://localhost:3001".parse::<HeaderValue>().unwrap())
                .allow_headers([AUTHORIZATION, CONTENT_TYPE])
                .allow_methods([Method::GET, Method::POST]),
        )
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
    JsonOrPlain(body): JsonOrPlain<CheckProofPayload>,
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

    if !signature_valid {
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
    )
    .await
    .map_err(|_| anyhow!("liteserver timeout"))??;

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

#[derive(Serialize, Deserialize)]
struct Claims {
    exp: u64,
    address: String,
}

#[async_trait]
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

// to make accept json with content-type: text/plain
struct JsonOrPlain<T>(T);

#[async_trait]
impl<S, T> FromRequest<S> for JsonOrPlain<T>
where
    S: Send + Sync,
    Json<T>: FromRequest<()>,
    T: 'static,
{
    type Rejection = Response;

    async fn from_request(mut req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type_header = req.headers().get(CONTENT_TYPE);
        let content_type = content_type_header.and_then(|value| value.to_str().ok());

        if let Some(content_type) = content_type {
            if content_type.starts_with("application/json")
                || content_type.starts_with("text/plain")
            {
                if content_type.starts_with("text/plain") {
                    let content_type = req
                        .headers_mut()
                        .get_mut(CONTENT_TYPE)
                        .expect("checked above");
                    *content_type = HeaderValue::from_static("application/json");
                }

                let Json(payload) = req
                    .extract::<Json<T>, _>()
                    .await
                    .map_err(|err| err.into_response())?;
                return Ok(Self(payload));
            }
        }

        Err(
            AppError::UnsupportedMedia(anyhow!("expected application/json content type"))
                .into_response(),
        )
    }
}
