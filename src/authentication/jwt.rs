use std::fs;
use std::path::Path;

use actix_web::cookie::time::Duration as ActixDuration;
use anyhow::Ok;
use anyhow::Result;
use chrono::Duration as ChronoDuration;
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::rngs::OsRng;
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn ensure_keys_exist() -> Result<()> {
    let private_key_path = "private.pem";
    let public_key_path = "public.pem";

    if !Path::new(private_key_path).exists() || !Path::new(public_key_path).exists() {
        println!("Generating a new RSA key pair...");

        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits)?;
        let public_key = private_key.to_public_key();

        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?
            .to_string();
        let public_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)?
            .to_string();

        fs::write(private_key_path, private_pem)?;
        fs::write(public_key_path, public_pem)?;

        println!("Keys generated: private.pem and public.pem");
    }

    Ok(())
}

pub fn generate_token(user_id: Uuid, expires_in: i64) -> Result<String, anyhow::Error> {
    ensure_keys_exist()?;

    let current_time = Utc::now();
    let actix_duration = ActixDuration::hours(expires_in);
    let duration_in_seconds = actix_duration.as_seconds_f32() as i64;

    let expiration =
        (current_time + ChronoDuration::seconds(duration_in_seconds)).timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiration,
    };

    let token = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(include_bytes!("private.pem"))?,
    )?;

    Ok(token)
}

// fn verify_jwt(token: &str) -> Result<Claims, anyhow::Error> {
//     let decoding_key = DecodingKey::from_rsa_pem(include_bytes!("private.pem"))?;
//     let validation = Validation {
//         leeway: 0,
//         validate_exp: true,
//         validate_nbf: false,
//         algorithms: vec![Algorithm::RS256],
//         required_spec_claims: todo!(),
//         reject_tokens_expiring_in_less_than: todo!(),
//         validate_aud: todo!(),
//         aud: todo!(),
//         iss: todo!(),
//         sub: todo!(),
//         validate_signature: todo!(),
//     };

//     let decoded_token = decode::<Claims>(token, &decoding_key, &validation)?;
//     Ok(decoded_token.claims)
// }
