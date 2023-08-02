#[macro_use]
extern crate rocket;
extern crate base64;
extern crate ed25519_dalek;
extern crate jwt;
extern crate tonlib;

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::{fairing::AdHoc, State};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tonlib::address::TonAddress;
use tonlib::client::{TonClient, TonClientBuilder, TonConnectionParams};
use tonlib::config::{MAINNET_CONFIG, TESTNET_CONFIG};
use tonlib::contract::TonContract;

pub mod utils;

const MAINNET_NETWORK: &'static str = "-239";
const TESTNET_NETWORK: &'static str = "-3";
const NETWORKS: [&'static str; 2] = [MAINNET_NETWORK, TESTNET_NETWORK];

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct Config {
    secret: String,
    ttl: u64,
    domain: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct TonProof {
    address: String,
    /// MAINNET = "-239",
    /// TESTNET = "-3"
    network: String,
    proof: TonProofItem,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct TonProofItem {
    domain: TonDomain,
    payload: String,
    signature: String,
    state_init: String,
    timestamp: u64,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct TonDomain {
    #[serde(rename = "lengthBytes")]
    length_bytes: u64,
    value: String,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct GeneratePayloadResponse {
    payload: String,
}

#[post("/generatePayload")]
fn generate_payload(config: &State<Config>) -> Result<Json<GeneratePayloadResponse>, String> {
    let payload = utils::generate_payload(&config.secret, config.ttl)?;
    Ok(Json(GeneratePayloadResponse { payload }))
}

const TON_PROOF_PREFIX: &'static str = "ton-proof-item-v2/";
const TON_CONNECT_PREFIX: &'static str = "ton-connect";

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct CheckProofResponse {
    token: String,
}

#[post("/checkProof", data = "<body>")]
async fn check_proof(
    config: &State<Config>,
    body: Json<TonProof>,
) -> Result<Json<CheckProofResponse>, String> {
    utils::check_payload(&config.secret, &body.proof.payload)
        .map_err(|e| format!("payload check failed: {}", e))?;

    if !NETWORKS.contains(&body.network.as_str()) {
        return Err(format!("undefined network: {}", body.network));
    }

    TonClient::set_log_verbosity_level(0);
    let client = TonClientBuilder::new()
        .with_connection_params(&TonConnectionParams {
            config: if &body.network == TESTNET_NETWORK {
                TESTNET_CONFIG.to_string()
            } else {
                MAINNET_CONFIG.to_string()
            },
            blockchain_name: None,
            use_callbacks_for_network: false,
            ignore_cache: false,
            keystore_dir: None,
        })
        .with_pool_size(10)
        .build()
        .await
        .map_err(|_| "failed to establishe connection to liteserver")?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards 🤷")
        .as_secs();
    if now >= body.proof.timestamp + config.ttl {
        return Err("proof has been expired".to_string());
    }

    if body.proof.domain.value != config.domain {
        return Err(format!("wrong domain: {}", body.proof.domain.value));
    }

    let domain_len = body.proof.domain.value.len();
    if domain_len != body.proof.domain.length_bytes as usize {
        return Err(format!("invalid domain length: {}", domain_len));
    }

    let addr = TonAddress::from_hex_str(&body.address)
        .map_err(|_| format!("invalid account: {}", body.address))?;

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

    let mut full_msg: Vec<u8> = vec![0xff, 0xff];
    full_msg.extend_from_slice(TON_CONNECT_PREFIX.as_bytes());
    full_msg.extend_from_slice(&msg_hash);

    let mut hasher = Sha256::new();
    hasher.update(full_msg);
    let full_msg_hash = hasher.finalize();

    let wallet_contract = TonContract::new(&client, &addr);
    let res = wallet_contract
        .run_get_method("get_public_key", &vec![])
        .await
        .map_err(|_| "get_public_key method failed")?;
    let pubkey_n = res
        .stack
        .get_biguint(0)
        .map_err(|_| "get_public_key parsing failed")?;
    let pubkey = PublicKey::from_bytes(&pubkey_n.to_bytes_be())
        .map_err(|_| "failed to deserialize pubkey")?;

    let sign_b = general_purpose::STANDARD
        .decode(&body.proof.signature)
        .map_err(|_| "failed to deserialize base64 signature")?;
    let signature = Signature::from_bytes(&sign_b).map_err(|_| "invalid signature")?;

    let check = pubkey.verify(&full_msg_hash, &signature).is_ok();
    if !check {
        return Err("proof verification failed".to_string());
    }

    let key: Hmac<Sha256> =
        Hmac::new_from_slice(&config.secret.as_bytes()).map_err(|_| "failed to create hmac key")?;
    let mut claims = BTreeMap::new();
    claims.insert("address", addr.to_base64_std());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards 🤷")
        .as_secs();
    claims.insert("exp", format!("{}", now + config.ttl));

    let token = claims
        .sign_with_key(&key)
        .map_err(|_| "failed to sign token")?;

    Ok(Json(CheckProofResponse { token }))
}

struct Token(String);

use rocket::http::Status;
use rocket::request::{self, FromRequest, Outcome, Request};

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Token {
    type Error = String;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let token = req.headers().get_one("token");
        match token {
            Some(token) => {
                // skip "Bearer "
                Outcome::Success(Token(token[7..].to_string()))
            }
            None => Outcome::Failure((Status::Unauthorized, "missing jwt".to_string())),
        }
    }
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct GetAccountInfoResponse {
    address: String,
}

#[get("/getAccountInfo")]
fn get_account_info(
    config: &State<Config>,
    token: Token,
) -> Result<Json<GetAccountInfoResponse>, String> {
    let key: Hmac<Sha256> =
        Hmac::new_from_slice(&config.secret.as_bytes()).map_err(|_| "failed to create hmac key")?;
    let claims: BTreeMap<String, String> = token
        .0
        .verify_with_key(&key)
        .map_err(|_| "jwt verification failed")?;

    let timestamp = claims
        .get("exp")
        .and_then(|exp| exp.parse::<u64>().ok())
        .ok_or("failed to parse exp".to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards 🤷")
        .as_secs();
    if now >= timestamp {
        return Err("token expired".to_string());
    }

    let address = claims.get("address").ok_or("failed to parse address")?;

    Ok(Json(GetAccountInfoResponse {
        address: address.clone(),
    }))
}

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::Response;

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new("Access-Control-Allow-Methods", "GET, POST"));
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(CORS)
        .mount("/ton-proof", routes![generate_payload, check_proof])
        .mount("/dapp", routes![get_account_info])
        .attach(AdHoc::config::<Config>())
}
