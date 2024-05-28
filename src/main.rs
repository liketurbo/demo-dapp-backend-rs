use crate::{
    dto::{CheckTonProof, TonNetwork},
    error::{anyhow, AppError},
};
use async_trait::async_trait;
use axum::{
    extract::{FromRequest, FromRequestParts, Request},
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
use dto::{CheckProofPayload, GenerateTonProofPayload, WalletAddress};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::timeout;
use tonlib::{
    cell::BagOfCells,
    client::TonClient,
    config::{MAINNET_CONFIG, TESTNET_CONFIG},
    contract::{TonContractFactory, TonContractInterface},
    wallet::{WalletDataHighloadV2R2, WalletDataV1V2, WalletDataV3, WalletDataV4, WalletVersion},
};
use tower_http::cors::{Any, CorsLayer};

mod dto;
mod error;

const SHARED_SECRET: &[u8] = "shhhh".as_bytes();
const DOMAIN: &str = "ton-connect.github.io";
const PAYLOAD_TTL: u64 = 3600; // 1 hour
const PROOF_TTL: u64 = 3600; // 1 hour

const JWT_KEYS: Lazy<JwtKeys> = Lazy::new(|| JwtKeys::new(SHARED_SECRET));
const KNOWN_HASHES: Lazy<HashMap<[u8; 32], WalletVersion>> = Lazy::new(|| {
    let mut known_hashes = HashMap::new();
    let all_versions = [
        WalletVersion::V1R1,
        WalletVersion::V1R2,
        WalletVersion::V1R3,
        WalletVersion::V2R1,
        WalletVersion::V2R2,
        WalletVersion::V3R1,
        WalletVersion::V3R2,
        WalletVersion::V4R1,
        WalletVersion::V4R2,
        WalletVersion::HighloadV1R1,
        WalletVersion::HighloadV1R2,
        WalletVersion::HighloadV2,
        WalletVersion::HighloadV2R1,
        WalletVersion::HighloadV2R2,
    ];
    all_versions.into_iter().for_each(|v| {
        let hash: [u8; 32] = v
            .code()
            .unwrap()
            .cell_hash()
            .unwrap()
            .try_into()
            .expect("all hashes [u8; 32], right?");
        known_hashes.insert(hash, v);
    });
    known_hashes
});

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route(
            "/ton-proof/generatePayload",
            post(generate_ton_proof_payload),
        )
        .route("/ton-proof/checkProof", post(check_ton_proof))
        .route("/dapp/getAccountInfo", get(get_account_info))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers([AUTHORIZATION, CONTENT_TYPE])
                .allow_methods([Method::GET, Method::POST]),
        );

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
async fn generate_ton_proof_payload() -> Result<Json<GenerateTonProofPayload>, AppError> {
    let mut payload: [u8; 48] = [0; 48];
    let mut rng = rand::thread_rng();
    rng.fill(&mut payload[0..8]);

    if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {
        let expire = n.as_secs() + PAYLOAD_TTL;
        let expire_be = expire.to_be_bytes();
        payload[8..16].copy_from_slice(&expire_be);
    } else {
        return Err(anyhow!("time went backwards 🤷").into());
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(SHARED_SECRET)?;
    mac.update(&payload[0..16]);
    let signature = mac.finalize().into_bytes();
    payload[16..48].copy_from_slice(&signature);

    let hex = hex::encode(&payload[0..32]);

    Ok(Json(GenerateTonProofPayload { payload: hex }))
}

async fn check_ton_proof(
    JsonOrPlain(body): JsonOrPlain<CheckProofPayload>,
) -> Result<Json<CheckTonProof>, AppError> {
    let data = hex::decode(body.proof.payload.clone())?;

    if data.len() != 32 {
        return Err(AppError::BadRequest(anyhow!(
            "invalid payload length, got {}, expected 32",
            data.len()
        )));
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(SHARED_SECRET)?;
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

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // check payload expiration
    let expire_b: [u8; 8] = data[8..16].try_into().expect("already checked length");
    let expire_d = u64::from_be_bytes(expire_b);
    if now > expire_d {
        return Err(AppError::BadRequest(anyhow!("payload expired")));
    }

    // check ton proof expiration
    if now > body.proof.timestamp + PROOF_TTL {
        return Err(AppError::BadRequest(anyhow!("ton proof has been expired")));
    }

    if body.proof.domain.value != DOMAIN {
        return Err(AppError::BadRequest(anyhow!(
            "wrong domain, got {}, expected {}",
            body.proof.domain.value,
            DOMAIN
        )));
    }

    if body.proof.domain.length_bytes != body.proof.domain.value.len() as u64 {
        return Err(AppError::BadRequest(anyhow!(
            "domain length mismatched against provided length bytes of {}",
            body.proof.domain.length_bytes
        )));
    }

    let ton_proof_prefix = "ton-proof-item-v2/";
    let mut msg: Vec<u8> = Vec::new();
    msg.extend_from_slice(ton_proof_prefix.as_bytes());
    msg.extend_from_slice(&body.address.workchain.to_be_bytes());
    msg.extend_from_slice(&body.address.hash_part);
    msg.extend_from_slice(&(body.proof.domain.length_bytes as u32).to_le_bytes());
    msg.extend_from_slice(body.proof.domain.value.as_bytes());
    msg.extend_from_slice(&body.proof.timestamp.to_le_bytes());
    msg.extend_from_slice(body.proof.payload.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(msg);
    let msg_hash = hasher.finalize();

    let mut full_msg: Vec<u8> = vec![0xff, 0xff];
    let ton_connect_prefix = "ton-connect";
    full_msg.extend_from_slice(ton_connect_prefix.as_bytes());
    full_msg.extend_from_slice(&msg_hash);

    let mut hasher = Sha256::new();
    hasher.update(full_msg);
    let full_msg_hash = hasher.finalize();

    let client = match body.network {
        TonNetwork::Mainnet => {
            TonClient::builder()
                .with_config(MAINNET_CONFIG)
                .build()
                .await?
        }
        TonNetwork::Testnet => {
            TonClient::builder()
                .with_config(TESTNET_CONFIG)
                .build()
                .await?
        }
    };

    let contract_factory = TonContractFactory::builder(&client).build().await?;
    let wallet_contract = contract_factory.get_contract(&body.address);
    let pubkey_bytes = match timeout(
        Duration::from_secs(10),
        wallet_contract.run_get_method("get_public_key", &vec![]),
    )
    .await
    {
        Ok(Ok(r)) => {
            let pubkey_n = r.stack.get_biguint(0)?;
            let pubkey_b: [u8; 32] = pubkey_n.to_bytes_be().try_into().map_err(|_| {
                anyhow!("failed to extract 32 bits long public from the wallet contract")
            })?;
            pubkey_b
        }
        Err(_) | Ok(Err(_)) => {
            let bytes = BASE64_STANDARD
                .decode(&body.proof.state_init)
                .map_err(|e| AppError::BadRequest(e.into()))?;
            let boc = BagOfCells::parse(&bytes).map_err(|e| AppError::BadRequest(e.into()))?;
            let hash: [u8; 32] = boc
                .single_root()
                .map_err(|e| AppError::BadRequest(e.into()))?
                .cell_hash()
                .map_err(|e| AppError::BadRequest(e.into()))?
                .try_into()
                .map_err(|_| AppError::BadRequest(anyhow!("invalid state_init length")))?;

            if hash != body.address.hash_part {
                return Err(AppError::BadRequest(anyhow!("wrong address in state_init")));
            }

            let root = boc.single_root().expect("checked above");
            let code = root
                .reference(0)
                .map_err(|e| AppError::BadRequest(e.into()))?;
            let data = root
                .reference(1)
                .map_err(|e| AppError::BadRequest(e.into()))?
                .as_ref()
                .clone();

            let code_hash: [u8; 32] = code
                .cell_hash()
                .map_err(|e| AppError::BadRequest(e.into()))?
                .try_into()
                .map_err(|_| AppError::BadRequest(anyhow!("invalid code of wallet")))?;
            let version = KNOWN_HASHES
                .get(&code_hash)
                .ok_or(AppError::BadRequest(anyhow!("not known wallet version")))?
                .clone();

            let pubkey_b = match version {
                WalletVersion::V1R1
                | WalletVersion::V1R2
                | WalletVersion::V1R3
                | WalletVersion::V2R1
                | WalletVersion::V2R2 => {
                    let data = WalletDataV1V2::try_from(data)
                        .map_err(|e| AppError::BadRequest(e.into()))?;
                    data.public_key
                }
                WalletVersion::V3R1 | WalletVersion::V3R2 => {
                    let data =
                        WalletDataV3::try_from(data).map_err(|e| AppError::BadRequest(e.into()))?;
                    data.public_key
                }
                WalletVersion::V4R1 | WalletVersion::V4R2 => {
                    let data =
                        WalletDataV4::try_from(data).map_err(|e| AppError::BadRequest(e.into()))?;
                    data.public_key
                }
                WalletVersion::HighloadV2R2 => {
                    let data = WalletDataHighloadV2R2::try_from(data)
                        .map_err(|e| AppError::BadRequest(e.into()))?;
                    data.public_key
                }
                _ => {
                    return Err(AppError::BadRequest(anyhow!(
                        "can't process given wallet version"
                    )));
                }
            };

            pubkey_b
        }
    };
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
        exp: now + PAYLOAD_TTL,
        address: body.address.to_base64_std(),
    };
    let token = encode(&Header::default(), &claims, &JWT_KEYS.encoding)?;

    Ok(Json(CheckTonProof { token }))
}

async fn get_account_info(claims: Claims) -> Result<Json<WalletAddress>, AppError> {
    Ok(Json(WalletAddress {
        address: claims.address,
    }))
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|e| AppError::Unauthorized(e.into()))?;

        let token_data =
            decode::<Claims>(bearer.token(), &JWT_KEYS.decoding, &Validation::default())
                .map_err(|e| AppError::Unauthorized(e.into()))?;

        let timestamp = token_data.claims.exp;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        if now >= timestamp {
            return Err(AppError::Unauthorized(anyhow!("token expired")));
        }

        Ok(token_data.claims)
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    exp: u64,
    address: String,
}

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

// To work with the [ton-connect/demo-dapp-with-backend example](https://github.com/ton-connect/demo-dapp-with-backend),
// which sends JSON requests with content-type: text/plain.
// In a real application, you probably won't need this part.
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
