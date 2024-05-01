#[derive(Clone)]
pub enum Algo {
  Algon2d = 0,
  Algon2i = 1,
  Algon2id = 2,
}
#[derive(Clone)]
pub struct Argon2 {
  algorithm: Algo,
}

#[cfg(test)]
mod test {
  use super::*;
}
