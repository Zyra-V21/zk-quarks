//! Witness and public input representation for R1CS

use ark_ff::Field;

#[derive(Debug, Clone)]
pub struct Witness<F: Field> {
    pub public_inputs: Vec<F>,
    pub assignments: Vec<F>, // witness values (w)
}

impl<F: Field> Witness<F> {
    /// Build the z vector = (io, 1, w)
    pub fn build_z(&self) -> Vec<F> {
        let mut z = Vec::with_capacity(self.public_inputs.len() + 1 + self.assignments.len());
        z.extend_from_slice(&self.public_inputs); // io
        z.push(F::one()); // constant 1
        z.extend_from_slice(&self.assignments); // w
        z
    }

    pub fn num_inputs(&self) -> usize {
        self.public_inputs.len()
    }

    pub fn num_witness(&self) -> usize {
        self.assignments.len()
    }
}

