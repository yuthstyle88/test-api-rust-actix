use std::fs;
use std::path::Path;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use actix_web::cookie::time::Duration as ActixDuration;
use anyhow::Ok;
use anyhow::Result;
use chrono::Duration as ChronoDuration;
use chrono::Utc;
use jsonwebtoken::decode;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::rngs::OsRng;
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
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

pub fn generate_token(
    user_id: Uuid,
    role_name: String,
    expires_in: i64,
) -> Result<String, anyhow::Error> {
    ensure_keys_exist()?;

    let current_time = Utc::now();
    let actix_duration = ActixDuration::minutes(expires_in);
    let duration_in_seconds = actix_duration.as_seconds_f32() as i64;

    let expiration =
        (current_time + ChronoDuration::seconds(duration_in_seconds)).timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        role: role_name,
        exp: expiration,
    };

    let private_key_pem = fs::read_to_string("private.pem")?;
    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?;

    let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)?;

    Ok(token)
}

pub fn verify_jwt(token: &str) -> Result<Claims, anyhow::Error> {
    let public_key_pem = fs::read_to_string("public.pem")?;
    let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;

    let decoded_token = decode::<Claims>(token, &decoding_key, &validation)?;

    let claims = decoded_token.claims;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as usize;
    if claims.exp < now {
        return Err(anyhow::anyhow!("Token has expired"));
    }

    Ok(claims)
}
