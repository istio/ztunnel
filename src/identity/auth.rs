use std::io;
use std::path::PathBuf;

use tonic::metadata::AsciiMetadataValue;
use tonic::service::Interceptor;
use tonic::{Code, Request, Status};

#[derive(Clone, Debug)]
pub enum AuthSource {
    Token(PathBuf),
}

impl AuthSource {
    pub fn load(&self) -> io::Result<Vec<u8>> {
        match self {
            AuthSource::Token(path) => {
                let t = std::fs::read(path)?;

                if t.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "token file exists, but was empty",
                    ));
                }
                Ok(t)
            }
        }
    }
}

impl Interceptor for AuthSource {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let token = self
            .load()
            .map_err(|e| Status::new(Code::Unauthenticated, e.to_string()))
            .map(|mut t| {
                let mut bearer: Vec<u8> = b"Bearer ".to_vec();
                bearer.append(&mut t);
                bearer
            })
            .and_then(|b| {
                AsciiMetadataValue::try_from(b)
                    .map_err(|e| Status::new(Code::Unauthenticated, e.to_string()))
            })?;

        request.metadata_mut().insert("authorization", token);
        Ok(request)
    }
}
