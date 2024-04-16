use std::ops::Add;

use crate::domain::value_object::{aes_type, blocks};

use super::domain::value_object::aes_gf::aesGF;
use aes_type::*;

pub(crate) trait CommonKeyRayer{
    fn forward(&self,blocks : Vec<u8>)->Vec<u8>;
    fn back(&self,blocks : Vec<u8>)->Vec<u8>;
}
#[derive(Debug)]
pub struct AES{
    key : Vec<u32>,
    sbox : [u8;256],
    inv_sbox:[u8;256],
    bit_type : BitType,
    mode : Mode
}
impl AES{
    pub fn new(key : Vec<u32>,bit_type : BitType,mode : Mode)->Self{
        let (sbox,inv) = make_sbox();
        Self { key: key, sbox: sbox, inv_sbox: inv,bit_type,mode}
    }
    fn key_expansion(&self)->Vec<u32>{
        let key = self.key.clone();
        let (nk,nr) = self.bit_type.nk_nr();
        let shift_word = |x : u32|x<<8 | x >> 24;
        let sub_word = |x:u32|{
            let connect = |x : [u8;4]|{
                    ((x[0] as u32) << 24) +
                    ((x[1] as u32) << 16) +
                    ((x[2] as u32) <<  8) +
                    ((x[3] as u32) <<  0)
            };
            let mut vec_u8 = x.to_be_bytes();
            let s = vec_u8.map(|x|self.sbox[x as usize]);
            connect(s)
        };
        // let key = shift_word(key[0]);
        // println!("{:x}",key);
        // let key = sub_word(key);
        // println!("{:?}",key);
        // key;
        let rcon : [u32;11] = [
            0x00000000, /* invalid */
            0x01000000, /* x^0 */
            0x02000000, /* x^1 */
            0x04000000, /* x^2 */
            0x08000000, /* x^3 */
            0x10000000, /* x^4 */
            0x20000000, /* x^5 */
            0x40000000, /* x^6 */
            0x80000000, /* x^7 */
            0x1B000000, /* x^4 + x^3 + x^1 + x^0 */
            0x36000000, /* x^5 + x^4 + x^2 + x^1 */
        ];
        let round = (nr as usize +1)*4;
        let key_length = nk as usize;
        let mut round_key : Vec<u32>  = Vec::new();
        round_key.extend(key.clone());
        // for k in round_key.iter().enumerate(){
        //     println!("round {} key is  {:x}",k.0,k.1);
        // }
        for i in key_length..round{
            //println!("round {}",i);
            let mut word : u32 = round_key[i-1];
            //println!("word {:x}",word);
            if i%key_length == 0 {
                word = shift_word(word);
                //println!("shif word {:x}",word);
                word = sub_word(word);
                //println!("sub word {:x}",word);
                //println!("rcon {:x}",rcon[i/key_length]);
                word = word ^ rcon[i/key_length];
                //println!("rcon xor {:x}",word);
            }else if 6<nk && i%key_length == 4{
                word = sub_word(word);
            }
            let pre_word = round_key[i-key_length].clone();
            //println!("pre word {:x}",pre_word);
            word = word ^ pre_word;
            //println!("pre xor {:x}",word);
            round_key.push(word);
        }
        round_key
    }
    pub fn encrypt(&self,input : Vec<u8>)->Vec<u8>{
        let mut block : Vec<u8> = input;
        let (nk,nr) = self.bit_type.nk_nr();
        let key = self.key_expansion();
        let inverse  = false;
        if !inverse {
        block = add_round_key(block,key[0..4].to_vec(), inverse);
        for i in 1..nr{
            //println!("round {}",i);
            //println!("input is  {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
            block = sub_bytes(block, inverse);
            //println!("after subbyte {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
            block = shift_row(block, inverse);
            //println!("after shift row {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
            block = mix_column(block, inverse);
            //println!("after mix column {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
            //println!("use key  Result: {}", key[4*i..4*(i+1)].iter().map(|x| format!("{:02X}", x)).collect::<String>()); 
            block = add_round_key(block, key[4*i..4*(i+1)].to_vec(), inverse);
            //println!("after add round key{}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
        }
        block = sub_bytes(block, inverse);
        //println!("after subbyte final Result: {}", block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
        block = shift_row(block, inverse);
        //println!("after shift row final Result: {}", block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
        //println!("use key final Result: {}", key[4*nr..4*(nr+1)].iter().map(|x| format!("{:02X}", x)).collect::<String>()); 
        block = add_round_key(block, key[4*nr..4*(nr+1)].to_vec(), inverse);
        }else{
            block = add_round_key(block, key[4*nr..4*(nr+1)].to_vec(), inverse);
            for i in (1..nr).rev(){
                block = shift_row(block, inverse);
                //println!("after shift row {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
                block = sub_bytes(block, inverse);
                //println!("after subbyte {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
                block = add_round_key(block, key[4*i..4*(i+1)].to_vec(), inverse);
                //println!("after add round key{}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
                block = mix_column(block, inverse);
                //println!("after mix column {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
            }
            
            block = shift_row(block, inverse);
            //println!("after shift row Result: {}", block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
            block = sub_bytes(block, inverse);
            //println!("after subbyte Result: {}", block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
            block = add_round_key(block, key[0..4].to_vec(), inverse);
            //println!("after add round key  Result: {}", block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
        }
        block
    }
    pub fn decrypt(input : Vec<u8>)->Vec<u8>{
        input
    }
}

pub(crate) fn make_sbox() -> ([u8;256],[u8;256]){
    let mut ret_sbox : [u8;256] = [0;256];
    let mut ret_inv_sbox : [u8;256] = [0;256];
    let shift = |x: u8,i : u8| x<<i | x >>(8-i);
    for i in 0..ret_sbox.len(){
        let t = aesGF{value :i as u8}.inv().value;
        ret_sbox[i] = t ^ shift(t,1) ^ shift(t,2) ^ shift(t,3) ^ shift(t,4) ^ 0x63u8;
        ret_inv_sbox[ret_sbox[i] as usize] = i as u8;
        //println!("{:x}",ret[i]);
    }
    (ret_sbox,ret_inv_sbox)
}

pub fn shift_row(blocks : Vec<u8>,inverse : bool) -> Vec<u8>{
    /*
    forward
     00 04 08 12 => 00 04 08 12
     01 05 09 13 => 05 09 13 01
     02 06 10 14 => 10 14 02 06
     03 07 11 15 => 15 03 07 11
     
    inverse
     00 04 08 12 => 00 04 08 12
     01 05 09 13 => 13 01 05 09
     02 06 10 14 => 10 14 02 06
     03 07 11 15 => 07 11 15 03

     */
    let mut ret = blocks.clone();
    for i in 0..4 {
        for j in 0..4{
            let slide = if inverse{
                (i+j)%4
            }else{ (i+4-j)%4};
            ret[4*slide +j] = blocks[4*i+j];
        }
        //println!("{:?}",ret);
    }
    ret
}


pub fn sub_bytes(blocks : Vec<u8>,inverse : bool) ->Vec<u8>{
    let (sbox,inv_sbox) = make_sbox();
    let mut ret = blocks;
    for mut item in ret.iter_mut(){
        if inverse{
            *item = inv_sbox[*item as usize];
        }else{
            *item = sbox[*item as usize];
        }
    }
    ret
}

pub fn mix_column(blocks: Vec<u8>,inverse : bool)->Vec<u8>{
    let blocks = blocks.into_iter().map(|x|aesGF{value:x}).collect::<Vec<aesGF>>();
    let mut ret :[aesGF;16] = [aesGF::default();16];
    for i in 0..4{
        let i = i *4;
        if !inverse {
        ret[i] = aesGF{value : 2}*blocks[i] + aesGF{value :3}*blocks[i+1] +   blocks[i+2] + blocks[i+3];
        ret[i +1] =   blocks[i] + aesGF{value : 2}*blocks[i+1] + aesGF{value :3}*blocks[i+2] + blocks[i+3];
        ret[i +2] =   blocks[i] +   blocks[i+1] + aesGF{value : 2}*blocks[i+2] + aesGF{value :3}*blocks[i+3];
        ret[i +3] = aesGF{value :3}*blocks[i] +   blocks[i+1] +   blocks[i+2] + aesGF{value : 2}*blocks[i+3];
        }else{

        ret[i] = aesGF{value : 0x0e}* blocks[i] + aesGF{value :0x0b}* blocks[i+1] + aesGF{value :0x0d}* blocks[i+2] + aesGF{value :0x09}* blocks[i+3];
        ret[i+1] = aesGF{value :0x09}* blocks[i] + aesGF{value : 0x0e}* blocks[i+1] +aesGF{value :0x0b}* blocks[i+2] + aesGF{value :0x0d}* blocks[i+3];
        ret[i+2] = aesGF{value :0x0d}* blocks[i] + aesGF{value :0x09}* blocks[i+1] +  aesGF{value : 0x0e}* blocks[i+2] + aesGF{value :0x0b}* blocks[i+3];
        ret[i+3] =aesGF{value :0x0b}* blocks[i] +aesGF{value :0x0d}* blocks[i+1] + aesGF{value :0x09}* blocks[i+2] +  aesGF{value : 0x0e}* blocks[i+3]; 
        }
    }
    let ret = ret.map(|x|{x.value}).to_vec();
    ret
}

pub fn add_round_key(blocks: Vec<u8>,key : Vec<u32>,inverse : bool)->Vec<u8>{
    let mut ret = blocks.clone();
    for i in 0..4{
        let key = key[i].to_be_bytes();
        //println!("round key is : {}", key.iter().map(|x| format!("{:02X}", x)).collect::<String>());
        for j in 0..4{
            //println!("round block {:x} , key {:x}",blocks[4*i +j],key[j]);
            ret[4*i +j] = blocks[4*i +j] ^ key[j];
        }
    }
    ret
}

pub fn shift_word(word : &mut [u8])->&mut[u8]{
    let mut word = word;
    word.rotate_left(2);
    word
}
pub fn sub_word(word : &mut [u8])->&mut[u8]{
    let (sbox,_) = make_sbox();
    for item in word.iter_mut(){
        *item = sbox[*item as usize];
    }
    word
}
pub fn key_exp(key : Vec<u32>,nk : usize,nr :usize)->Vec<u32>{
    let shift_word = |x : u32|x<<8 | x >> 24;
    let sub_word = |x:u32|{
        let connect = |x : [u8;4]|{
                ((x[0] as u32) << 24) +
                ((x[1] as u32) << 16) +
                ((x[2] as u32) <<  8) +
                ((x[3] as u32) <<  0)
        };
        let (sbox,_) = make_sbox();
        let mut vec_u8 = x.to_be_bytes();
        let s = vec_u8.map(|x|sbox[x as usize]);
        connect(s)
    };
    // let key = shift_word(key[0]);
    // println!("{:x}",key);
    // let key = sub_word(key);
    // println!("{:?}",key);
    // key;
    let rcon : [u32;11] = [
        0x00000000, /* invalid */
        0x01000000, /* x^0 */
        0x02000000, /* x^1 */
        0x04000000, /* x^2 */
        0x08000000, /* x^3 */
        0x10000000, /* x^4 */
        0x20000000, /* x^5 */
        0x40000000, /* x^6 */
        0x80000000, /* x^7 */
        0x1B000000, /* x^4 + x^3 + x^1 + x^0 */
        0x36000000, /* x^5 + x^4 + x^2 + x^1 */
    ];
    let round = (nr as usize +1)*4;
    let key_length = nk as usize;
    let mut round_key : Vec<u32>  = Vec::new();
    round_key.extend(key.clone());
    // for k in round_key.iter().enumerate(){
    //     println!("round {} key is  {:x}",k.0,k.1);
    // }
    for i in key_length..round{
        //println!("round {}",i);
        let mut word : u32 = round_key[i-1];
        //println!("word {:x}",word);
        if i%key_length == 0 {
            word = shift_word(word);
            //println!("shif word {:x}",word);
            word = sub_word(word);
            //println!("sub word {:x}",word);
            //println!("rcon {:x}",rcon[i/key_length]);
            word = word ^ rcon[i/key_length];
            //println!("rcon xor {:x}",word);
        }else if 6<nk && i%key_length == 4{
            word = sub_word(word);
        }
        let pre_word = round_key[i-key_length].clone();
        //println!("pre word {:x}",pre_word);
        word = word ^ pre_word;
        //println!("pre xor {:x}",word);
        round_key.push(word);
    }
    round_key
}

pub fn cipher(block :Vec<u8>,key : Vec<u32>,inverse : bool)->Vec<u8>{
    let mut block : Vec<u8> = block;
    let nr = 10;
    let nk = 4;
    let key = key_exp(key, nk, nr);
    let nr = nr as usize;
    let nk = nk as usize;
    if !inverse {
    block = add_round_key(block,key[0..4].to_vec(), inverse);
    for i in 1..nr{
        //println!("round {}",i);
        //println!("input is  {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
        block = sub_bytes(block, inverse);
        //println!("after subbyte {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
        block = shift_row(block, inverse);
        //println!("after shift row {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
        block = mix_column(block, inverse);
        //println!("after mix column {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
        //println!("use key  Result: {}", key[4*i..4*(i+1)].iter().map(|x| format!("{:02X}", x)).collect::<String>()); 
        block = add_round_key(block, key[4*i..4*(i+1)].to_vec(), inverse);
        //println!("after add round key{}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
    }
    block = sub_bytes(block, inverse);
    //println!("after subbyte final Result: {}", block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
    block = shift_row(block, inverse);
    //println!("after shift row final Result: {}", block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
    //println!("use key final Result: {}", key[4*nr..4*(nr+1)].iter().map(|x| format!("{:02X}", x)).collect::<String>()); 
    block = add_round_key(block, key[4*nr..4*(nr+1)].to_vec(), inverse);
    }else{
        block = add_round_key(block, key[4*nr..4*(nr+1)].to_vec(), inverse);
        for i in (1..nr).rev(){
            block = shift_row(block, inverse);
            //println!("after shift row {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
            block = sub_bytes(block, inverse);
            //println!("after subbyte {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
            block = add_round_key(block, key[4*i..4*(i+1)].to_vec(), inverse);
            //println!("after add round key{}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
            block = mix_column(block, inverse);
            //println!("after mix column {}  Result: {}",i, block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
        }
        
        block = shift_row(block, inverse);
        //println!("after shift row Result: {}", block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
        block = sub_bytes(block, inverse);
        //println!("after subbyte Result: {}", block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
        block = add_round_key(block, key[0..4].to_vec(), inverse);
        //println!("after add round key  Result: {}", block.iter().map(|x| format!("{:02X}", x)).collect::<String>());
    }
    block
}

pub fn padding_pkcs_7(input : Vec<u8>)->Vec<u8>{
    let block_byte = (input.len()/16 + 1)*16;
    let value = (block_byte - input.len()) as u8;
    let mut ret = input.clone();
    for i in 0..value{
        ret.push(value);
    }
    println!("padding size {}",ret.len());
    ret
}


#[cfg(test)]
mod test{
    use super::*;

    #[test]
    fn test_vector1(){
    //PLAINTEXT = 6bc1bee22e409f96e93d7e117393172a
    //KEY = 2b7e1516 28aed2a6 abf71588 09cf4f3c
    //CIPHERTEXT = 3ad77bb40d7a3660a89ecaf32466ef97
    let input = vec![0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a];
    let key = vec![0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c];

    let input = cipher(input, key.clone(), false);
    assert_eq!(input,hex::decode("3ad77bb40d7a3660a89ecaf32466ef97").unwrap());
    let input = cipher(input, key.clone(), true);
    assert_eq!(input,hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap());

    }
    #[test]
    fn test_vector2(){
        
    //plain=ae2d8a571e03ac9c9eb76fac45af8e51
    //key=2b7e151628aed2a6abf7158809cf4f3c
    //cipher=f5d3d58503b9699de785895a96fdbaaf
    let input = hex::decode("ae2d8a571e03ac9c9eb76fac45af8e51").expect("test ae2d error");
    let key = vec![0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c];

    let input = cipher(input, key.clone(), false);
    assert_eq!(input,hex::decode("f5d3d58503b9699de785895a96fdbaaf").unwrap());
    let input = cipher(input, key.clone(), true);
    assert_eq!(input,hex::decode("ae2d8a571e03ac9c9eb76fac45af8e51").unwrap());
    }
    
    #[test]
    fn test_vector3(){
    //test vector1
    //plain=32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
    //key=2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
    //cipher= 39 02 dc 19
    //        25 dc 11 6a
    //        84 09 85 0b
    //        1d fb 97 32
    let input = vec![0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34];
    let key :Vec<u32> = vec![0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c];

    let input = cipher(input, key.clone(), false);
    assert_eq!(input,hex::decode("3925841d02dc09fbdc118597196a0b32").unwrap());
    let input = cipher(input, key.clone(), true);
    assert_eq!(input,hex::decode("3243f6a8885a308d313198a2e0370734").unwrap());

    }

    #[test]
    fn test_vector4(){
    //PLAINTEXT: 00112233445566778899aabbccddeeff
    //KEY: 000102030405060708090a0b0c0d0e0f
    //output: 69c4e0d86a7b0430d8cdb78070b4c55a
    //test vector 2

    let input = vec![0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];
    let key = vec![0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f];


    let input = cipher(input, key.clone(), false);
    assert_eq!(input,hex::decode("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap());
    let input = cipher(input, key.clone(), true);
    assert_eq!(input,hex::decode("00112233445566778899aabbccddeeff").unwrap());
    }


    #[test]
    fn test_aes(){
        let input = hex::decode("ae2d8a571e03ac9c9eb76fac45af8e51").expect("test ae2d error");
        let key = vec![0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c];
        let bit_type = aes_type::BitType::Aes128;
        let mode = aes_type::Mode::Ecb;
        let aes : AES = AES::new(key.clone(),bit_type,mode);
        let input = aes.encrypt(input);
        assert_eq!(input,hex::decode("f5d3d58503b9699de785895a96fdbaaf").unwrap());
    }

}