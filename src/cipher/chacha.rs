type Block = [u32; 16];
#[derive(Clone)]
pub struct ChaCha {
  state: Block,
}

impl ChaCha {
  fn new() -> Self {
    Self { state: [0; 16] }
  }
  fn quarter_round(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    /*
    1.  a += b; d ^= a; d <<<= 16;
    2.  c += d; b ^= c; b <<<= 12;
    3.  a += b; d ^= a; d <<<= 8;
    4.  c += d; b ^= c; b <<<= 7;
    */
    //let rot32 = |x: u32, n: u32| x << n | x >> (32 - n);
    let mut a = a;
    let mut b = b;
    let mut c = c;
    let mut d = d;
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);
    [a, b, c, d]
  }

  fn init(key: &[u32], counter: u32, nonce: &[u32]) -> Block {
    /*
    The ChaCha20 state is initialized as follows:

    o  The first four words (0-3) are constants: 0x61707865, 0x3320646e,
       0x79622d32, 0x6b206574.

    o  The next eight words (4-11) are taken from the 256-bit key by
       reading the bytes in little-endian order, in 4-byte chunks.

    o  Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
       word is enough for 256 gigabytes of data.

    o  Words 13-15 are a nonce, which should not be repeated for the same
       key.  The 13th word is the first 32 bits of the input nonce taken
       as a little-endian integer, while the 15th word is the last 32
       bits.

        cccccccc  cccccccc  cccccccc  cccccccc
        kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
        kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
        bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

        c=constant k=key b=blockcount n=nonce */

    /*const 0x61707865, 0x3320646e,
      0x79622d32, 0x6b206574.
    */
    if !(key.len() == 8 && nonce.len() == 3) {
      panic!("block key size or nonce is not varid");
    }
    let mut block: Block = [0; 16];
    block[0] = 0x61707865;
    block[1] = 0x3320646e;
    block[2] = 0x79622d32;
    block[3] = 0x6b206574;

    (0..key.len()).into_iter().for_each(|i| {
      block[4 + i] = key[i];
    });
    block[12] = counter;

    (0..nonce.len()).into_iter().for_each(|i| {
      block[13 + i] = nonce[i];
    });

    println!("block init is {:?}", block);
    block
  }

  fn block(key: &[u32], counter: u32, nonce: &[u32]) -> Block {
    let state = ChaCha::init(key, counter, nonce);
    let inner_block = || {
      let mut block: Block = [0; 16];
      block
    };

    state
  }
}
#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn quarter_test() {
    /*
    o  a = 0x11111111
    o  b = 0x01020304
    o  c = 0x9b8d6f43
    o  d = 0x01234567
    o  c = c + d = 0x77777777 + 0x01234567 = 0x789abcde
    o  b = b ^ c = 0x01020304 ^ 0x789abcde = 0x7998bfda
    o  b = b <<< 7 = 0x7998bfda <<< 7 = 0xcc5fed3c




    o  a = 0xea2a92f4
    o  b = 0xcb1cf8ce
    o  c = 0x4581472e
    o  d = 0x5881c4bb
    */

    let state: [u32; 4] = [0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567];
    let ans: [u32; 4] = [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb];
    let state = ChaCha::quarter_round(state[0], state[1], state[2], state[3]);
    assert_eq!(state, ans);
  }

  #[test]
  fn block_test() {
    /*

    For a test vector, we will use the following inputs to the ChaCha20
    block function:

    o  Key = 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:
       14:15:16:17:18:19:1a:1b:1c:1d:1e:1f.  The key is a sequence of
       octets with no particular structure before we copy it into the
       ChaCha state.

    o  Nonce = (00:00:00:09:00:00:00:4a:00:00:00:00)

    o  Block Count = 1.

    After setting up the ChaCha state, it looks like this:

    ChaCha state with the key setup.

        61707865  3320646e  79622d32  6b206574
        03020100  07060504  0b0a0908  0f0e0d0c
        13121110  17161514  1b1a1918  1f1e1d1c
        00000001  09000000  4a000000  00000000

    After running 20 rounds (10 column rounds interleaved with 10
    "diagonal rounds"), the ChaCha state looks like this:

    ChaCha state after 20 rounds

        837778ab  e238d763  a67ae21e  5950bb2f
        c4f2d0c7  fc62bb2f  8fa018fc  3f5ec7b7
        335271c2  f29489f3  eabda8fc  82e46ebd
        d19c12b4  b04e16de  9e83d0cb  4e3c50a2

    Finally, we add the original state to the result (simple vector or
    matrix addition), giving this:

    ChaCha state at the end of the ChaCha20 operation

        e4e7f110  15593bd1  1fdd0f50  c47120a3
        c7f4d1c7  0368c033  9aaa2204  4e6cd4c3
        466482d2  09aa9f07  05d7c214  a2028bd9
        d19c12b5  b94e16de  e883d0cb  4e3c50a2
     */
    let le_to_u32 = |x: &[u8]| {
      let mut ret = 0u32;
      println!("le is {:x?} ", x);
      for x in x.iter().enumerate() {
        ret ^= (*x.1 as u32) << (8u32 * x.0 as u32);
      }
      ret
    };

    let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      .expect("key is invalid")
      .chunks(4)
      .map(le_to_u32)
      .collect::<Vec<u32>>();
    let nonce = hex::decode(b"000000090000004a00000000")
      .expect("nonce is invalid")
      .chunks(4)
      .map(le_to_u32)
      .collect::<Vec<u32>>();
    let counter = 1u32;
    println!(
      "key is {:x?} , nonce is {:x?} , counter is {}",
      key, nonce, counter
    );
    let chacha = ChaCha::init(&key, counter, &nonce);
    println!("init vec is {:x?}", chacha);
  }
}
