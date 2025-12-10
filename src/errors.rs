//! Error types for Quarks implementation

use thiserror::Error;

#[derive(Error, Debug)]
pub enum QuarksError {
    #[error("Invalid field element: {0}")]
    InvalidFieldElement(String),
    
    #[error("R1CS verification failed: {0}")]
    R1CSVerificationFailed(String),
    
    #[error("Polynomial evaluation error: {0}")]
    PolynomialError(String),
    
    #[error("Sum-check protocol failed: {0}")]
    SumCheckFailed(String),
    
    #[error("Commitment verification failed: {0}")]
    CommitmentFailed(String),
    
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}

pub type Result<T> = std::result::Result<T, QuarksError>;

