use std::sync::Arc;

use ark_ff::PrimeField;
use itertools::izip;

use crate::{error::Error, parameters::PoseidonParams};

#[derive(Clone, Debug)]
pub struct Poseidon<F: PrimeField> {
    pub(crate) params: Arc<PoseidonParams<F>>,
}
impl<F: PrimeField> Poseidon<F> {
    pub fn new(params: &Arc<PoseidonParams<F>>) -> Self {
        Poseidon {
            params: params.clone(),
        }
    }

    pub fn permutation(&self, input: Vec<F>) -> Result<Vec<F>, Error> {
        let t = self.params.t;
        if input.len() != t {
            return Err(Error::InvalidParameters);
        }
        let mut current_state = input;
        for r in 0..self.params.rounds_f_beginning {
            self.add_rc(&mut current_state, &self.params.round_constants[r]);
            self.sbox(&mut current_state);
            current_state = PoseidonParams::mat_vec_mul(&self.params.mds, &current_state);
        }
        let p_end = self.params.rounds_f_beginning + self.params.rounds_p;
        self.add_rc(&mut current_state, &self.params.opt_round_constants[0]);
        current_state = PoseidonParams::mat_vec_mul(&self.params.m_i, &current_state);
        for r in self.params.rounds_f_beginning..p_end {
            current_state[0] = self.sbox_p(&current_state[0]);
            if r < p_end - 1 {
                current_state[0].add_assign(
                    &self.params.opt_round_constants[r + 1 - self.params.rounds_f_beginning][0],
                );
            }
            current_state = self.cheap_matmul(&current_state, p_end - r - 1);
        }
        for r in p_end..self.params.rounds {
            self.add_rc(&mut current_state, &self.params.round_constants[r]);
            self.sbox(&mut current_state);
            current_state = PoseidonParams::mat_vec_mul(&self.params.mds, &current_state);
        }
        Ok(current_state)
    }

    fn sbox(&self, input: &mut [F]) {
        input.iter_mut().for_each(|el| *el = self.sbox_p(el));
    }

    fn sbox_p(&self, input: &F) -> F {
        match self.params.d {
            3 => {
                let input2 = input.square();
                let mut out = input2;
                out.mul_assign(input);
                out
            }
            5 => {
                let input2 = input.square();
                let mut out = input2.square();
                out.mul_assign(input);
                out
            }
            7 => {
                let input2 = input.square();
                let mut out = input2.square();
                out.mul_assign(&input2);
                out.mul_assign(input);
                out
            }
            _ => input.pow([self.params.d as u64]),
        }
    }

    fn cheap_matmul(&self, input: &[F], r: usize) -> Vec<F> {
        let v = &self.params.v[r];
        let w_hat = &self.params.w_hat[r];
        let t = self.params.t;
        let mut new_state = vec![F::zero(); t];
        new_state[0] = self.params.mds[0][0];
        new_state[0].mul_assign(&input[0]);
        for (inp, w) in izip!(input.iter().skip(1), w_hat.iter()) {
            let mut tmp = w.to_owned();
            tmp.mul_assign(inp);
            new_state[0].add_assign(&tmp);
        }
        for (n, inp, v) in izip!(new_state.iter_mut().skip(1), input.iter().skip(1), v.iter()) {
            input[0].clone_into(n);
            n.mul_assign(v);
            n.add_assign(inp);
        }
        new_state
    }

    fn add_rc(&self, input: &mut [F], rc: &[F]) {
        debug_assert_eq!(input.len(), rc.len());
        input.iter_mut().zip(rc.iter()).for_each(|(a, b)| {
            a.add_assign(b);
        });
    }
}
