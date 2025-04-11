use std::io::Read;

use super::aes::{self, add_round_key, mix_column, shift_row, sub_bytes, AES};


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
  iv : Vec<u128>,
  ad : Vec<u128>,
  message: Vec<u128>,
  cipher_text : Vec<u128>
}

  fn aes_round(state: u128,key : u128)->u128{
    let mut state = state.to_le_bytes().to_vec();
    let aes = AES::new();
    let inverse = false;
    state = sub_bytes(state,inverse);
    state = shift_row(state, inverse);
    state = mix_column(state, inverse);
    state = add_round_key(state, u128_to_u32_vec(key.clone()), inverse);

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

  fn new() -> Self{
    let state = Vec::new();
    let iv = Vec::new();
    let ad = Vec::new();
    let message = Vec::new();
    let cipher_text = Vec::new();
    Self { state: state, iv: iv, ad: ad,message : message,cipher_text:cipher_text}
  }
  fn init(&mut self,key : Vec<u128>) -> Vec<u128>{
    let const_vec : Vec<u128> = vec![0;2];
    let mut state : Vec<u128> = vec![0;5];
    state[0] = key[0] ^ self.iv[0];
    state[1] = const_vec[0];
    state[2] = const_vec[1];
    state[3] = key[0] ^ const_vec[0];
    state[4] = key[0] ^ const_vec[1];

    if !self.ad.is_empty() {
      state = with_ad(state,self.ad.clone());
    }
    self.state = state.clone();
    state.clone()
  }
  
  fn enc(&mut self,plane : Vec<u128>)->Vec<u128>{
    //3.4
    let adlen = (self.ad.len() + 127) / 128;
    let messagelen = (self.message.len() + 127)/128;
    let mut state = self.state.clone();
    let mut cipher_text : Vec<u128> = Vec::new();
    for i in 0..messagelen{
      let c = self.message[i] ^ state[1] ^ state[4] ^ (state[2] & state[3]);
      cipher_text.push(c);
      state = state_update128(state, self.message[i]);
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
  use super::*;

  #[test]
  fn aesround_test(){
    let state :u128 = 0;
    let key : u128 = 0;
    let aes_block = aes_round(state, key);
    println!("aes round test {:?}",aes_block);
  }

    #[test]
  fn aegis_test(){
    let state :u128 = 0;
    let key : u128 = 0;
    let aes_block = aes_round(state, key);
    let aegis = Aegis::new();
    println!("aes round test {:?}",aes_block);
  }
}