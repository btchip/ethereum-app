mod bn254;
pub mod error;
mod parameters;
mod poseidon;

use ark_bn254::Fr;
use poseidon::Poseidon;

use crate::{
    bn254::{
        circom_t2::get_t2_params, circom_t3::get_t3_params, circom_t4::get_t4_params,
        circom_t5::get_t5_params, circom_t6::get_t6_params,
    },
    error::Error,
};

pub fn poseidon_hash(inputs: &[Fr]) -> Result<Fr, Error> {
    let mut state = vec![Fr::from(0)];
    state.extend_from_slice(inputs);

    let out = match state.len() {
        2 => Poseidon::new(&get_t2_params()).permutation(state)?,
        3 => Poseidon::new(&get_t3_params()).permutation(state)?,
        4 => Poseidon::new(&get_t4_params()).permutation(state)?,
        5 => Poseidon::new(&get_t5_params()).permutation(state)?,
        6 => Poseidon::new(&get_t6_params()).permutation(state)?,
        _ => return Err(Error::UnsupportedInputLength(state.len())),
    };

    Ok(out[0])
}
