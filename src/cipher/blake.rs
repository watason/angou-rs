use std::ops::*;

#[derive(Debug)]
struct Blake2 {
  h: [u64; 8],
}

#[derive(Debug, Default, Clone)]
struct Key {
  h: Vec<u64>,
}
impl Blake2 {
  //IV
  const IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
  ];

  fn new() -> Self {
    Self { h: Self::IV }
  }

  pub fn hash(&self, m: Vec<u8>, nn: u8, key: Key) -> Vec<u64> {
    let m = m
      .chunks(8)
      .map(|x| {
        let mut ret = 0u64;
        for x in x.iter().enumerate() {
          ret ^= (*x.1 as u64) << (8u64 * x.0 as u64)
        }
        println!(" map num is {:x?}", ret);
        ret
      })
      .collect::<Vec<u64>>();
    println!("le message is {:?}", m);
    let message_len: u128 = m.len() as u128;
    let key = key;
    let kk = key.h.len() as u64;
    let nn: u64 = nn.into();

    let mut h = Self::IV.to_vec();
    let mut cbyte_compress: u128 = 0;
    let mut cbyte_remain = message_len;

    // Parameter block p[0]
    //  h[0] = h[0] ^ 0x0101kknn
    //  h[0] := h[0] ^ 0x01010000 ^ (kk << 8) ^ nn
    h[0] = h[0] ^ 0x01010000u64 ^ kk.wrapping_shl(8) ^ nn;

    println!("{:?}", m);
    let last_num = m.len() / 128;
    let mut counter = 0u128;
    let hdash = m.chunks(128).enumerate().fold(h, |hash, chunk| {
      let ret = Self::compress(
        hash,
        chunk.1.to_vec(),
        (chunk.0 as u128) * 128u128,
        chunk.0 == last_num,
      );
      println!("round is {:x?}", ret);
      ret
    });
    // while cbyte_remain > 128u128 {
    //   let chunk = &m[cbyte_compress..(cbyte_compress + 128)].into();
    //   cbyte_compress += 128;
    //   cbyte_remain -= 128;
    //   h = Self::compress(h, chunk, cbyte_compress, false);
    // }

    // let chunk = &m[cbyte_compress..(cbyte_compress + 128)].into();
    // cbyte_compress += 128;
    // cbyte_remain -= 128;

    //h = Self::compress(h, chunk, cbyte_compress, true);

    hdash
  }

  fn compress(h: Vec<u64>, chunk: Vec<u64>, t: u128, last: bool) -> Vec<u64> {
    const SIGMA: [usize; 160] = [
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0,
      2, 11, 7, 5, 3, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4, 7, 9, 3, 1, 13, 12, 11,
      14, 2, 6, 5, 10, 4, 0, 15, 8, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13, 2, 12, 6,
      10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8,
      11, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2,
      13, 7, 1, 4, 10, 5, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    ];
    let mut v: Vec<u64> = h.clone();
    v.extend(Self::IV);

    v[12] ^= u64::try_from(t).ok().unwrap();
    v[13] ^= u64::try_from(t >> 64).ok().unwrap();

    if last {
      v[14] ^= u64::MAX;
    }

    let m = chunk;
    /*
      |      |   v := G( v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]] )
      |      |   v := G( v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]] )
      |      |   v := G( v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]] )
      |      |   v := G( v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]] )
      |      |
      |      |   v := G( v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]] )
      |      |   v := G( v, 1, 6, 11, 12, m[s[10]], m[s[11]] )
      |      |   v := G( v, 2, 7,  8, 13, m[s[12]], m[s[13]] )
      |      |   v := G( v, 3, 4,  9, 14, m[s[14]], m[s[15]] )
    */
    for i in 0..11 {
      println!("v {} is {:x?}", i, v);
      let imod = (i % 10) * 16;
      let s = SIGMA[imod..(imod + 16)].to_vec();

      for j in 0..4 {
        (v[j], v[j + 4], v[j + 8], v[j + 12]) = Blake2::g(
          v[j],
          v[j + 4],
          v[j + 8],
          v[j + 12],
          m[s[j * 2]],
          m[s[j * 2 + 1]],
        );
      }
      (v[0], v[5], v[10], v[15]) = Blake2::g(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]]);
      (v[1], v[6], v[11], v[12]) = Blake2::g(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
      (v[2], v[7], v[8], v[13]) = Blake2::g(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]]);
      (v[3], v[4], v[9], v[14]) = Blake2::g(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]]);
    }
    h.iter()
      .enumerate()
      .map(|(i, x)| x ^ v[i] ^ v[i + 8])
      .collect::<Vec<u64>>()
  }

  fn g(mut a: u64, mut b: u64, mut c: u64, mut d: u64, x: u64, y: u64) -> (u64, u64, u64, u64) {
    //let rotate = |x : u64,n : usize|{(x >> n) | (x << (64 - n))};
    a = a.wrapping_add(b).wrapping_add(x);
    d = (d ^ a).rotate_right(32);
    //println!("{:064b}", d);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_right(24);
    //println!("{:064b}", b);

    a = a.wrapping_add(b).wrapping_add(y);
    //println!("{:064b}", a);
    d = (d ^ a).rotate_right(16);
    //println!("{:064b}", d);
    c = c.wrapping_add(d);
    //println!("{:064b}", c);
    b = (b ^ c).rotate_right(63);
    //println!("{:064b}", b);
    (a, b, c, d)
  }
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn g_test() {
    let a = 0u64;
    let b = 1u64;
    let c = 2u64;
    let d = 3u64;
    let x = 4u64;
    let y = 5u64;
    let ret = Blake2::g(a, b, c, d, x, y);
    println!("{:?}", ret);
  }
  #[test]
  fn f_test() {
    let h: Vec<u64> = vec![0; 8];
    let chunk: Vec<u64> = vec![0; 16];
    let t: u128 = 0u128;
    let last = false;
    let v = Blake2::compress(h, chunk, t, last);
    println!("v is {:x?}", v);
  }

  #[test]
  fn blake2b_test() {
    let blake: Blake2 = Blake2::new();
    let key: Key = Key { h: Vec::new() };
    let mut m: Vec<u8> = vec![0; 128];
    m[0] = 0x61;
    m[1] = 0x62;
    m[2] = 0x63;
    let nn = 64;
    let ret = blake.hash(m, nn, key);
    println!("hash is {:x?}", ret);
  }
}
