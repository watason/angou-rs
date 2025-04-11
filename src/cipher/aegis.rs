use std::io::Read;

use super::aes::{self, add_round_key, mix_column, shift_row, sub_bytes, Key, AES};

use crate::domain::value_object::aes_type;
fn u128_to_u32_vec(value: u128) -> Vec<u32> {
    let mut result = Vec::with_capacity(4);
    
    for i in 0..4 {
        result.push(((value >> (i * 32)) & 0xFFFFFFFF) as u32);
    }
    
    result
}

#[derive(Debug,Default,Clone)]
struct Aegis{
  state : Vec<u128>,
  iv : u128,
  ad : Vec<u8>,
  message: Vec<u128>,
  cipher_text : Vec<u128>
}

  fn aes_round(state: u128,key : u128)->u128{
    let mut state = state.to_le_bytes().to_vec();
    let aes = AES::new();
    let inverse = false;

    let u128_to_u32 =|x:u128|{
                    vec![
                    (x >>96 )as u32 ,
                    (x >> 64 ) as u32,
                    (x >>32 )as u32 ,
                     x as u32,                    ]
    };
    let key = u128_to_u32(key);
    let bit_type = aes_type::BitType::Aes128;
    let mode = aes_type::Mode::Ecb;

    let exkey : Key= Key::new(key.clone(),bit_type.clone(),mode.clone());
    let exkey = aes.key_expansion(exkey);

    state = sub_bytes(state,inverse);
    state = shift_row(state, inverse);
    state = mix_column(state, inverse);
    state = add_round_key(state, exkey.clone(), inverse);

    u128::from_le_bytes(state.try_into().unwrap())
  }

fn state_update128(state : Vec<u128>, message : u128) -> Vec<u128>{
    let mut ret = state.clone();
    ret[0] = aes_round(state[4],message);
    ret[1] = aes_round(state[1],ret[0]);
    ret[2] = aes_round(state[2],ret[1]);
    ret[3] = aes_round(state[3],ret[2]);
    ret[4] = aes_round(state[4],ret[3]);
    
    ret
}


fn with_ad(state : Vec<u128>,ad : Vec<u128>) -> Vec<u128>{
    let ad = ad;
    let mut state = state;


    for i in 0..ad.len(){
      state = state_update128(state, ad[i]);
    }
    state
}

impl Aegis{
  // Fibonacci数列 mod 256の32バイト定数
  const FIBONACCI_CONSTANT: [u8; 32] = [
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
    0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
    0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
  ];
  fn new() -> Self{
    let state = Vec::new();
    let iv : u128 = 0;
    let ad :Vec<u8> = Vec::new() ;
    let message = Vec::new();
    let cipher_text = Vec::new();
    Self { state: state, iv: iv, ad: ad,message : message,cipher_text:cipher_text}
  }
  fn init(&mut self,key : u128) -> Vec<u128>{
    //3.2.1
    let mut state : Vec<u128> = self.state.clone();
    let mut m : Vec<u128> = Vec::new();
    let const0 =u128::from_le_bytes(Aegis::FIBONACCI_CONSTANT[0..16].try_into().unwrap());
    let const1 = u128::from_le_bytes(Aegis::FIBONACCI_CONSTANT[16..32].try_into().unwrap());
    
    println!("const0 const1 is {:x?}   {:x?} ",const0,const1);
    state[0] = key ^ self.iv;
    state[1] = const1;
    state[2] = const0;
    state[3] = key ^ const0;
    state[4] = key ^ const1;

    // if !self.ad.is_empty() {
    //   //state = with_ad(state,self.ad.clone());
    // }

    //3.2.2
    for i in 0..5 {
      m.push(key);
      m.push(key^self.iv);
    }
    //3.2.3
    for mi in m{
      state = state_update128(state, mi);
    }

    self.state = state.clone();
    state.clone()
  }
  
  fn enc(&mut self,plane : Vec<u128>)->Vec<u128>{
    //3.4
    let adlen = (self.ad.len() + 127) / 128;
    let messagelen = plane.len() ;
    let mut state = self.state.clone();
    let mut cipher_text : Vec<u128> = Vec::new();

    println!("eagis enc state is {:?} ",state);
    for i in 0..messagelen{
      println!("state 2 3 and is {:?} {:?} {:?}",state[2],state[3],state[2]&state[3]);
      println!("state 1 4 and is {:?} {:?} {:?}",state[1],state[4],state[1]^state[4]);
      println!("state 1 423 and is {:?} {:?} {:?}",state[1],state[4],state[1]^state[4]^(state[2]&state[3]));
      println!("state plane 23 and is {:?} {:?} {:?}",plane[i],state[2],plane[i]^state[2]);
      let c = plane[i] ^ state[1] ^ state[4] ^ (state[2] & state[3]);

      println!("eagis enc cipher is {:?} ",c);
      cipher_text.push(c);
      state = state_update128(state, plane[i]);
      
    }
    self.state = state;
    self.cipher_text = cipher_text.clone();
    cipher_text

  }
  fn finalize(&mut self) ->Vec<u128>{
    //3.5.1
    let mut tmp = self.state[2];
    let adlen = self.ad.len() as u128;
    let messagelen = self.message.len() as u128;
    tmp ^= adlen | messagelen;

    //3.5.2
    let mut state = self.state.clone();
    //why 0~6?
    for i in 0..6{
      state = state_update128(state, tmp);
    }
    //3.5.3
    let tag = state.iter().fold(0,|acc,part|acc ^ part);
    self.state = state.clone();

    state
  }
  fn dec(&mut self,cipher : Vec<u128>)-> Vec<u128>{

    let mut plane_text = Vec::new();
    let mut state = self.state.clone();
    //3.6.1
    let v = self.message.len();
    for i in 0..v-1{
      let plane = cipher[i] ^ state[1] ^ state[4] ^ (state[2] & state[3]);
      plane_text.push(plane.clone());
      state = state_update128(state, plane);
    }
    plane_text
  }
}
#[cfg(test)]
mod test{
  use crate::cipher;

use super::*;

  #[test]
  fn aesround_test(){
    let state :u128 = u128::from_str_radix("000102030405060708090a0b0c0d0e0f",16).unwrap();
    let key : u128 = u128::from_str_radix("101112131415161718191a1b1c1d1e1f", 16).unwrap();
    
    let ans :u128 = u128::from_str_radix("7a7b4e5638782546a8c0477a3b813f43",16).unwrap();
    let aes_block = aes_round(state, key);
    println!("aes round test {:x?}",aes_block);
    println!("aes round test ans  {:x?}",ans);
    assert_eq!(ans,aes_block,"aesround test is error ");
  }

    #[test]
  fn aegis_init_test(){
    let plane_text :u128 = 0;
    let key : u128 = 0;
    let iv :u128 = 0;
    let state = vec![0;5];
    let message = Vec::new();
    let cihper = Vec::new();
    let mut aegis = Aegis{state,iv:iv,ad:Vec::new(),message,cipher_text:cihper};

    let cipher_tex = aegis.init(key.clone());

    println!("aegis initialize test {:?}",cipher_tex);
  }
      #[test]
  fn aegis_cipher_test(){
    let mut plane_text :Vec<u128> = Vec::new();
    plane_text.push(0);
    let key : u128 = 0;
    let iv :u128 = 0;
    let state = vec![0;5];
    let message = Vec::new();
    let cihper = Vec::new();
    let mut aegis = Aegis{state,iv:iv,ad:Vec::new(),message,cipher_text:cihper};

    let state = aegis.init(key.clone());
    println!("aegis cipher state is {:?} ",state);
    let cipher_text = aegis.enc(plane_text);

    let ans :u128 = u128::from_str_radix("951b050fa72b1a2fc16d2e1f01b07d7e",16).unwrap();
    println!("aegis cipher_text test {:x?}",cipher_text);
    println!("aegis ans test {:x?}",ans);
    assert_eq!(ans,cipher_text[0],"aegis cipher test error");
  }

}