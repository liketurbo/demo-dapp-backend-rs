use hex;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub fn generate_payload(secret: &str, ttl: u64) -> Result<String, String> {
    let mut payload: [u8; 48] = [0; 48];
    let mut rng = rand::thread_rng();
    rng.fill(&mut payload[0..8]);

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => {
            let expire = n.as_secs() + ttl;
            let expire_be = expire.to_be_bytes();
            payload[8..16].copy_from_slice(&expire_be);
        }
        Err(_) => return Err("SystemTime before UNIX EPOCH!".to_string()),
    }

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| "HMAC can take key of any size")?;
    mac.update(&payload[0..16]);
    let sign = mac.finalize();
    let sign_bytes = sign.into_bytes();
    payload[16..48].copy_from_slice(&sign_bytes);

    let hex_string = hex::encode(&payload[0..32]);
    Ok(hex_string)
}

pub fn check_payload(secret: &str, payload: &str) -> Result<(), String> {
    let d = hex::decode(payload).map_err(|e| e.to_string())?;

    if d.len() != 32 {
        return Err("invalid payload length".to_string());
    }

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| "HMAC can take key of any size")?;
    mac.update(&d[0..16]);
    let sign = mac.finalize();
    let sign_bytes = sign.into_bytes();
    let sign_valid = d
        .iter()
        .skip(16)
        .zip(sign_bytes.iter().take(16))
        .all(|(a, b)| a == b);

    if !sign_valid {
        return Err("invalid payload signature".to_string());
    }

    let expire_b: [u8; 8] = d[8..16].try_into().expect("already checked length");
    let expire_d = u64::from_be_bytes(expire_b);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards 🤷")
        .as_secs();

    if now >= expire_d {
        return Err("payload expired".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_payload() {
        let secret = "mysecretkey";
        let ttl = 3600; // 1 hour
        match generate_payload(secret, ttl) {
            Ok(payload) => {
                assert_eq!(payload.len(), 64);
            }
            Err(error) => {
                panic!("generate_payload failed with error: {}", error);
            }
        }
    }

    #[test]
    fn test_check_payload_valid() {
        let secret = "mysecretkey";
        let ttl = 3600; // 1 hour

        let payload = generate_payload(secret, ttl).expect("Failed to generate payload");

        match check_payload(secret, &payload) {
            Ok(_) => {
                assert!(true); // passed
            }
            Err(error) => {
                panic!("check_payload failed with error: {}", error);
            }
        }
    }

    #[test]
    fn test_check_payload_invalid_signature() {
        let secret = "mysecretkey";
        let ttl = 3600; // 1 hour

        let mut payload = generate_payload(secret, ttl).expect("failed to generate payload");

        let ch = payload.pop();
        if ch == Some('0') {
            payload.push('1');
        } else {
            payload.push('0');
        }

        match check_payload(secret, &payload) {
            Ok(_) => {
                panic!("check_payload should have failed for invalid signature");
            }
            Err(error) => {
                assert_eq!(error, "invalid payload signature"); // passed
            }
        }
    }

    #[test]
    fn test_check_payload_expired() {
        let secret = "mysecretkey";
        let ttl = 0;

        let payload = generate_payload(secret, ttl).expect("failed to generate payload");

        match check_payload(secret, &payload) {
            Ok(_) => {
                panic!("check_payload should have failed for expired payload");
            }
            Err(error) => {
                assert_eq!(error, "payload expired"); // passed
            }
        }
    }
}
