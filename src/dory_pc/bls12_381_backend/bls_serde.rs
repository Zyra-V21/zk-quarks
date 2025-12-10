//! Dory serialization traits for BLS12-381 wrapper types

use super::{Bls381Fr, Bls381G1, Bls381G2, Bls381GT};
use crate::dory_pc::primitives::serialization::{Compress, SerializationError, Valid, Validate};
use crate::dory_pc::primitives::{DoryDeserialize, DorySerialize};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid as ArkValid};
use std::io::{Read, Write};

impl Valid for Bls381Fr {
    fn check(&self) -> Result<(), SerializationError> {
        self.0
            .check()
            .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))
    }
}

impl DorySerialize for Bls381Fr {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match compress {
            Compress::Yes => self
                .0
                .serialize_compressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
            Compress::No => self
                .0
                .serialize_uncompressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        match compress {
            Compress::Yes => self.0.compressed_size(),
            Compress::No => self.0.uncompressed_size(),
        }
    }
}

impl DoryDeserialize for Bls381Fr {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => ark_bls12_381::Fr::deserialize_compressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
            Compress::No => ark_bls12_381::Fr::deserialize_uncompressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
        };

        if matches!(validate, Validate::Yes) {
            inner
                .check()
                .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))?;
        }

        Ok(Bls381Fr(inner))
    }
}

impl Valid for Bls381G1 {
    fn check(&self) -> Result<(), SerializationError> {
        self.0
            .check()
            .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))
    }
}

impl DorySerialize for Bls381G1 {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match compress {
            Compress::Yes => self
                .0
                .serialize_compressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
            Compress::No => self
                .0
                .serialize_uncompressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        match compress {
            Compress::Yes => self.0.compressed_size(),
            Compress::No => self.0.uncompressed_size(),
        }
    }
}

impl DoryDeserialize for Bls381G1 {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => ark_bls12_381::G1Projective::deserialize_compressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
            Compress::No => ark_bls12_381::G1Projective::deserialize_uncompressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
        };

        if matches!(validate, Validate::Yes) {
            inner
                .check()
                .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))?;
        }

        Ok(Bls381G1(inner))
    }
}

impl Valid for Bls381G2 {
    fn check(&self) -> Result<(), SerializationError> {
        self.0
            .check()
            .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))
    }
}

impl DorySerialize for Bls381G2 {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match compress {
            Compress::Yes => self
                .0
                .serialize_compressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
            Compress::No => self
                .0
                .serialize_uncompressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        match compress {
            Compress::Yes => self.0.compressed_size(),
            Compress::No => self.0.uncompressed_size(),
        }
    }
}

impl DoryDeserialize for Bls381G2 {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => ark_bls12_381::G2Projective::deserialize_compressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
            Compress::No => ark_bls12_381::G2Projective::deserialize_uncompressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
        };

        if matches!(validate, Validate::Yes) {
            inner
                .check()
                .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))?;
        }

        Ok(Bls381G2(inner))
    }
}

impl Valid for Bls381GT {
    fn check(&self) -> Result<(), SerializationError> {
        self.0
            .check()
            .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))
    }
}

impl DorySerialize for Bls381GT {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match compress {
            Compress::Yes => self
                .0
                .serialize_compressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
            Compress::No => self
                .0
                .serialize_uncompressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        match compress {
            Compress::Yes => self.0.compressed_size(),
            Compress::No => self.0.uncompressed_size(),
        }
    }
}

impl DoryDeserialize for Bls381GT {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => ark_bls12_381::Fq12::deserialize_compressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
            Compress::No => ark_bls12_381::Fq12::deserialize_uncompressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
        };

        if matches!(validate, Validate::Yes) {
            inner
                .check()
                .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))?;
        }

        Ok(Bls381GT(inner))
    }
}

