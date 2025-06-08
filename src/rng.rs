pub trait Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}
