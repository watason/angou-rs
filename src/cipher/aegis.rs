use std::{io::Read, ops::Index};

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
  ad : Vec<u128>,
  message: Vec<u128>,
  cipher_text : Vec<u128>
}

  fn aes_round(state: u128,key : u128)->u128{
    let mut state = state.to_be_bytes().to_vec();
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

    //println!("aes round state is {:x?} " ,state);
    let state = u128::from_be_bytes(state.try_into().unwrap());
    state
  }

fn state_update128(state : Vec<u128>, message : u128) -> Vec<u128>{
    let mut ret = state.clone();
    //println!("state update128 is {:x?}  {:x?}",ret,message);
    ret[0] = aes_round(state[4],state[0] ^ message);
    ret[1] = aes_round(state[0],state[1]);
    ret[2] = aes_round(state[1],state[2]);
    ret[3] = aes_round(state[2],state[3]);
    ret[4] = aes_round(state[3],state[4]);
    ret
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
    let ad :Vec<u128> = Vec::new() ;
    let message = Vec::new();
    let cipher_text = Vec::new();
    Self { state: state, iv: iv, ad: ad,message : message,cipher_text:cipher_text}
  }
  fn init(&mut self,key : u128) -> Vec<u128>{
    //3.2.1
    let mut state : Vec<u128> = self.state.clone();
    let mut m : Vec<u128> = Vec::new();
    let const0 =u128::from_be_bytes(Aegis::FIBONACCI_CONSTANT[0..16].try_into().unwrap());
    let const1 = u128::from_be_bytes(Aegis::FIBONACCI_CONSTANT[16..32].try_into().unwrap());
    
    println!("const0 const1 is {:x?}   {:x?} ",const0,const1);
    state[0] = key ^ self.iv;
    state[1] = const1;
    state[2] = const0;
    state[3] = key ^ const0;
    state[4] = key ^ const1;

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
    
    println!("init state is {:x?}",state);
    if !self.ad.is_empty() {
      state = self.with_ad();
    }
    state.clone()
  }
  
  fn enc(&mut self,plane : Vec<u128>)->Vec<u128>{
    //3.4
    let messagelen = plane.len() ;
    self.message = plane.clone();
    let mut state = self.state.clone();
    let mut cipher_text : Vec<u128> = Vec::new();


    if messagelen == 0{
      return cipher_text;
    }
    println!("eagis enc state is {:?} ",state);
    for i in 0..messagelen{
      let c = plane[i] ^ state[1] ^ state[4] ^ (state[2] & state[3]);

      //println!("eagis enc cipher is {:?} ",c);
      cipher_text.push(c);
      state = state_update128(state, plane[i]);
      
    }
    self.state = state.clone();
    self.cipher_text = cipher_text.clone();
      
    println!("eagis enc cipher is {:?} {:x?} ",self.cipher_text,cipher_text);
    println!("eagis enc state is {:?} ",self.state);
    
    cipher_text

  }
  
fn with_ad(&mut self) -> Vec<u128>{
    let ad = self.ad.clone();
    let mut state = self.state.clone();
    let adlen = ad.len();


    for i in 0..adlen{
      state = state_update128(state, ad[i]);
    }
    self.state = state.clone();
    state
}
  fn finalize(&mut self) ->u128{
    //3.5.1
    let adlen = self.ad.len() as u64;
    let messagelen = self.message.len() as u64;
    let mut state = self.state.clone();

    println!("adlen is {:?} , message len is {:?} , or is {:b}",adlen,messagelen,((adlen as u128) << 64)|(messagelen as u128));
    let tmp = state[3] ^ ((messagelen as u128) << 64 | (adlen as u128));
    //3.5.2
    let tag0 = state.iter().take(5).fold(0,|acc,part|acc ^ part);
    println!("tmp tag is {} {:?} ",0,tag0);
    //why 0~6?
    for i in 0..7{
      state = state_update128(state, tmp);
      println!("finalize state is {:x?}",state);
      
      let tag = state.iter().take(5).fold(0,|acc,part|acc ^ part);
      println!("tmp tag is {} {:?} ",i,u128::from_be(tag));
    }
    //3.5.3
    let tag = state.iter().take(5).fold(0,|acc,part|acc ^ part);
    self.state = state;

    println!("finalize tag is {:x?} {:?} ",tag,tag);
    tag
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
    let tag = aegis.finalize();
    println!("aegis cipher tag test {:x?}",tag);
    
    let ans :u128 = u128::from_str_radix("951b050fa72b1a2fc16d2e1f01b07d7e",16).unwrap();
    let ans_tag = u128::from_str_radix("a7d2a99773249542f422217ee888d5f1", 16).unwrap();
    //println!("aegis cipher_text test {:x?}",cipher_text);
    //println!("aegis ans test {:x?}",ans);
    println!("aegis anstag test {:?}",ans_tag);


    assert_eq!(ans,cipher_text[0],"aegis cipher test error");
    //assert_eq!(ans_tag,tag,"aegis cipher tag test error");
    

  }

//associated data: 128 bits plaintext: 128 bits
// K128 = 00000000000000000000000000000000
// IV128 = 00000000000000000000000000000000
// assoc. data = 00000000000000000000000000000000
// plaintext = 00000000000000000000000000000000
// ciphertext = 10b0dee65a97d751205c128a992473a1
// tag = 46dcb9ee93c46cf13731d41b9646c131
      #[test]
  fn aegis_cipher_test2(){
    let mut plane_text :Vec<u128> = Vec::new();
    plane_text.push(0);
    
    let mut ad :Vec<u128> = Vec::new();
    ad.push(0);
    let key : u128 = 0;
    let iv :u128 = 0;
    let state = vec![0;5];
    let message = Vec::new();
    let cihper = Vec::new();
    let mut aegis = Aegis{state,iv:iv,ad:ad,message,cipher_text:cihper};

    let state = aegis.init(key.clone());
    println!("aegis cipher state is {:?} ",state);
    let cipher_text = aegis.enc(plane_text);
    let tag = aegis.finalize().to_be();
    
    let ans :u128 = u128::from_str_radix("10b0dee65a97d751205c128a992473a1",16).unwrap();
    let ans_tag = u128::from_str_radix("46dcb9ee93c46cf13731d41b9646c131", 16).unwrap();
    println!("aegis cipher_text test {:x?}",cipher_text);
    println!("aegis ans test {:x?}",ans);
    
    println!("aegis cipher tag test {:x}",tag);
    println!("aegis anstag test {:x}",ans_tag);
    println!("aegis tag ^ anstag test {:b}",tag^ans_tag);
    

    assert_eq!(ans,cipher_text[0],"aegis cipher test error");
    //assert_eq!(ans_tag,tag,"aegis cipher tag test error");
    

  }


// associated data: 64 bits plaintext: 256 bits
// K128 = 10010000000000000000000000000000
// IV128 = 10000200000000000000000000000000
// assoc. data = 0001020304050607
// plaintext = 000102030405060708090a0b0c0d0e0f
// 101112131415161718191a1b1c1d1e1f
// ciphertext = e08ec10685d63c7364eca78ff6e1a1dd
// fdfc15d5311a7f2988a0471a13973fd7
// tag = 27e84b6c4cc46cb6ece8f1f3e4aa0e78
     #[test]
  fn aegis_cipher_test3(){
    let mut plane_text :Vec<u128> = vec![
u128::from_str_radix("000102030405060708090a0b0c0d0e0f",16).unwrap(),u128::from_str_radix("101112131415161718191a1b1c1d1e1f",16).unwrap()
    ];
    
    let mut ad :Vec<u128> = vec![
u128::from_str_radix("0001020304050607",16).unwrap()
    ];
    let key : u128 = u128::from_str_radix("10010000000000000000000000000000",16).unwrap();
    let iv :u128 = u128::from_str_radix("10000200000000000000000000000000",16).unwrap();
    let state = vec![0;5];
    let message = Vec::new();
    let cihper = Vec::new();
    let mut aegis = Aegis{state,iv:iv,ad:ad,message,cipher_text:cihper};

    let state = aegis.init(key.clone());
    println!("aegis cipher state is {:?} ",state);
    let cipher_text = aegis.enc(plane_text);
    let tag = aegis.finalize().to_be();
    
    let ans :u128 = u128::from_str_radix("e08ec10685d63c7364eca78ff6e1a1dd",16).unwrap();
    let ans_tag = u128::from_str_radix("27e84b6c4cc46cb6ece8f1f3e4aa0e78", 16).unwrap();
    println!("aegis cipher_text test {:x?}",cipher_text);
    println!("aegis ans test {:x?}",ans);
    
    println!("aegis cipher tag test {:x}",tag);
    println!("aegis anstag test {:x}",ans_tag);
    println!("aegis tag ^ anstag test {:b}",tag^ans_tag);
    

    assert_eq!(ans,cipher_text[0],"aegis cipher test error");
    //assert_eq!(ans_tag,tag,"aegis cipher tag test error");
    

  }


}