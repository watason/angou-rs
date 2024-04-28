use std::ops::*;

#[derive(Debug)]
struct Blake2 {
  h: [u64; 8],
}

#[derive(Debug, Default, Clone)]
struct Key {
  h: Vec<u8>,
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

  pub fn hash(&self, m: Vec<u8>, nn: u8, key: Key) -> Vec<u8> {
    let key = key;
    let kk = key.h.len() as u64;
    let nn: u64 = nn.into();
    let padding = |x: Vec<u8>| {
      let mut ret = x;
      let diff = 128 - ret.len() % 128;
      for i in 0..diff {
        ret.push(0);
      }
      ret
    };

    let le_to_u64 = |x: &[u8]| {
      let mut ret = 0u64;
      for x in x.iter().enumerate() {
        ret ^= (*x.1 as u64) << (8u64 * x.0 as u64);
      }
      ret
    };

    //message block
    let ll = m.len() % 128;
    let m = padding(m);
    let m = m.chunks(8).map(le_to_u64).collect::<Vec<u64>>();

    //key block (option)
    let key_block = if kk > 0 {
      padding(key.h)
        .chunks(8)
        .map(le_to_u64)
        .collect::<Vec<u64>>()
    } else {
      Vec::new()
    };

    //concat
    let m = [key_block, m].concat();
    //println!("le message is {:?}", m);
    //println!("key + message len is {} and init {:?}", m.len(), m);
    let mut h = Self::IV.to_vec();

    // Parameter block p[0]
    //  h[0] = h[0] ^ 0x0101kknn
    //  h[0] := h[0] ^ 0x01010000 ^ (kk << 8) ^ nn
    h[0] = h[0] ^ 0x01010000u64 ^ kk.wrapping_shl(8) ^ nn;

    //println!(" init h is {:x?}", h);
    let last_num = m.len() / 16 - 1;
    let hdash = m.chunks(16).enumerate().fold(h, |hash, chunk| {
      let last = chunk.0 == last_num;
      let ret = Self::compress(
        hash,
        chunk.1.to_vec(),
        if !last {
          ((chunk.0 + 1) as u128) * 128u128
        } else {
          //todo! change
          ((chunk.0) as u128) * 128u128 + ll as u128
        },
        last,
      );
      ret
    });

    //u64 to le bytes
    hdash.into_iter().flat_map(|x| x.to_le_bytes()).collect()
  }

  fn compress(h: Vec<u64>, chunk: Vec<u64>, t: u128, last: bool) -> Vec<u64> {
    /*
          Round   |  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 |
        ----------+-------------------------------------------------+
         SIGMA[0] |  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 |
         SIGMA[1] | 14 10  4  8  9 15 13  6  1 12  0  2 11  7  5  3 |
         SIGMA[2] | 11  8 12  0  5  2 15 13 10 14  3  6  7  1  9  4 |
         SIGMA[3] |  7  9  3  1 13 12 11 14  2  6  5 10  4  0 15  8 |
         SIGMA[4] |  9  0  5  7  2  4 10 15 14  1 11 12  6  8  3 13 |
         SIGMA[5] |  2 12  6 10  0 11  8  3  4 13  7  5 15 14  1  9 |
         SIGMA[6] | 12  5  1 15 14 13  4 10  0  7  6  3  9  2  8 11 |
         SIGMA[7] | 13 11  7 14 12  1  3  9  5  0 15  4  8  6  2 10 |
         SIGMA[8] |  6 15 14  9 11  3  0  8 12  2 13  7  1  4 10  5 |
         SIGMA[9] | 10  2  8  4  7  6  1  5 15 11  9 14  3 12 13  0 |
        ----------+-------------------------------------------------+
    */
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

    // println!(
    //   "compress t is {:?} hi {} low {}",
    //   t,
    //   t >> 64,
    //   u64::try_from(t).ok().unwrap()
    // );
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
    for i in 0..12 {
      //println!("before v {} is {:x?}", i, v);
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

      //println!("after v {} is {:x?}", i, v);
    }
    (0..8).map(|i| h[i] ^ v[i] ^ v[i + 8]).collect()
  }

  fn g(a: u64, b: u64, c: u64, d: u64, x: u64, y: u64) -> (u64, u64, u64, u64) {
    //let rotate = |x : u64,n : usize|{(x >> n) | (x << (64 - n))};
    let mut a = a;
    let mut b = b;
    let mut c = c;
    let mut d = d;

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
  use core::hash;

  use super::*;

  #[test]
  fn g_test() {
    /* (a,b,c,d) = g(a,b,c,d,x,y) = 3298534884874, 870327276700175364, 435160339815202818, 435160314045399040
       input (a,b,c,d,x,y) = (0,1,2,3,4,5)
       g function test
    */
    let answer = (
      3298534884874,
      870327276700175364,
      435160339815202818,
      435160314045399040,
    );
    let a = 0u64;
    let b = 1u64;
    let c = 2u64;
    let d = 3u64;
    let x = 4u64;
    let y = 5u64;
    let ret = Blake2::g(a, b, c, d, x, y);
    //println!("{:?}", ret);
    assert_eq!(answer, ret);
  }
  #[test]
  fn f_test() {
    /*
    f() = 6a09e667f2bdc948, bb67ae8584caa73b, 3c6ef372fe94f82b, a54ff53a5f1d36f1, 510e527fade682d1, 9b05688c2b3e6c1f, 1f83d9abfb41bd6b, 5be0cd19137e2179
    h = [0;8]
    chunk = [0;16]
    t = 0
    last = false

    */
    let answer: Vec<u64> = vec![
      0x4d3f506019115ac7,
      0x2fa2733d57dc0ab8,
      0xd1e1c1129f845613,
      0x65061dc9c8e902ac,
      0x8a5c682f464ae8ce,
      0x3d9eb972a409d768,
      0x61d9c25d696ae005,
      0xee2e6936bda0ebc9,
    ];
    let h: Vec<u64> = vec![0; 8];
    let chunk: Vec<u64> = vec![0; 16];
    let t: u128 = 0u128;
    let last = false;
    let v = Blake2::compress(h, chunk, t, last);
    //println!("test f v is {:x?}", v);
    assert_eq!(answer, v);
  }

  #[test]
  fn blake2b_test() {
    /* hash = BA 80 A5 3F 98 1C 4D 0D 6A 27 97 B6 9F 12 F6 E9
              4C 21 2F 14 68 5A C4 B7 4B 12 BB 6F DB FF A2 D1
              7D 87 C5 39 2A AB 79 2D C2 52 D5 DE 45 33 CC 95
              18 D3 8A A8 DB F1 92 5A B9 23 86 ED D4 00 99 23
       text = "abc"
       blake2b
    */
    let hash_ = "BA 80 A5 3F 98 1C 4D 0D 6A 27 97 B6 9F 12 F6 E9
                 4C 21 2F 14 68 5A C4 B7 4B 12 BB 6F DB FF A2 D1 
                 7D 87 C5 39 2A AB 79 2D C2 52 D5 DE 45 33 CC 95 
                 18 D3 8A A8 DB F1 92 5A B9 23 86 ED D4 00 99 23"
      .split_whitespace()
      .flat_map(|x| hex::decode(x).expect("test blake2b answer error"))
      .collect::<Vec<u8>>();
    let blake: Blake2 = Blake2::new();
    let key: Key = Key { h: Vec::new() };
    let mut m: Vec<u8> = vec![0; 3];
    m[0] = 0x61;
    m[1] = 0x62;
    m[2] = 0x63;
    let nn = 64;
    let ret = blake.hash(m, nn, key);
    //println!("hash is {:02x?}", ret);
    assert_eq!(hash_, ret);
  }
  #[test]
  fn blake2b_test2() {
    /*
    hash = A8ADD4BDDDFD93E4877D2746E62817B116364A1FA7BC148D95090BC7333B3673F82401CF7AA2E4CB1ECD90296E3F14CB5413F8ED77BE73045B13914CDCD6A918
    text = "The quick brown fox jumps over the lazy dog"
    blake2b
     */
    let hash_ = hex::decode("A8ADD4BDDDFD93E4877D2746E62817B116364A1FA7BC148D95090BC7333B3673F82401CF7AA2E4CB1ECD90296E3F14CB5413F8ED77BE73045B13914CDCD6A918").expect("test2 blake2b answer error");
    let blake = Blake2::new();
    let key: Key = Key { h: Vec::new() };
    let str: String = "The quick brown fox jumps over the lazy dog".to_string();
    let m: Vec<u8> = str.as_bytes().to_vec();
    let nn = 64;
    let ret = blake.hash(m, nn, key);
    //println!("hash test2 is {:02x?}", ret);
    assert_eq!(ret, hash_);
  }

  #[test]
  fn blake2b_key_test() {
    /* output= 17de517e1278d00ac7a6bcf048881aa9a972e6b5cef843d3c61d3e252068a2f526c999f45cd96b172509d085b59170e388f845750c812781df582be3fc4a1972
       text = "abc"
       key  = "abc"
    */
    let hash_ = hex::decode("17de517e1278d00ac7a6bcf048881aa9a972e6b5cef843d3c61d3e252068a2f526c999f45cd96b172509d085b59170e388f845750c812781df582be3fc4a1972").expect("key test error");
    let blake = Blake2::new();
    let mut h = Vec::new();
    h.push(0x61);
    h.push(0x62);
    h.push(0x63);
    let key = Key { h: h };
    let mut m: Vec<u8> = vec![0; 3];
    m[0] = 0x61;
    m[1] = 0x62;
    m[2] = 0x63;
    let nn = 64;
    let ret = blake.hash(m, nn, key);
    //println!("test key is {:x?}", ret);
    assert_eq!(ret, hash_);
  }

  #[test]
  fn blake2b_key_test2() {
    /* output= 08ddabfa369e135c79ab30c8c8f954030ff0e9ff3d4f3eb23f4b2769b62283513e245ac2ee6dff13f4f9e7da87d042bc75f09fcb712a85ccbfe52527bba329a5
       text = "test"
       key  = "test"
    */
    let hash_ = hex::decode("08ddabfa369e135c79ab30c8c8f954030ff0e9ff3d4f3eb23f4b2769b62283513e245ac2ee6dff13f4f9e7da87d042bc75f09fcb712a85ccbfe52527bba329a5").expect("key test error");
    let blake = Blake2::new();
    let h = "test".as_bytes().to_vec();
    let key = Key { h: h };
    let mut m: Vec<u8> = "test".as_bytes().to_vec();
    let nn = 64;
    let ret = blake.hash(m, nn, key);
    //println!("test key is {:x?}", ret);
    assert_eq!(ret, hash_);
  }
}
