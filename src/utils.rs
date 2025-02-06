use regex::Regex;

pub fn is_valid_email(email: &str) -> bool {
    let email_regex = Regex::new(r"^[\w\.-]+@[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}$").unwrap();
    
    email_regex.is_match(email)
}