use std::fmt;

#[derive(Debug)]
pub enum ShodanError {
    Api(String),
    Http(reqwest::Error),
    Json(serde_json::Error),
    Io(std::io::Error),
}

impl fmt::Display for ShodanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShodanError::Api(msg) => write!(f, "{}", msg),
            ShodanError::Http(e) => write!(f, "HTTP error: {}", e),
            ShodanError::Json(e) => write!(f, "JSON parse error: {}", e),
            ShodanError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for ShodanError {}

impl From<reqwest::Error> for ShodanError {
    fn from(e: reqwest::Error) -> Self {
        ShodanError::Http(e)
    }
}

impl From<serde_json::Error> for ShodanError {
    fn from(e: serde_json::Error) -> Self {
        ShodanError::Json(e)
    }
}

impl From<std::io::Error> for ShodanError {
    fn from(e: std::io::Error) -> Self {
        ShodanError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ShodanError>;
