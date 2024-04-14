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
    
    pub fn encrypt(&self,input : Vec<u8>)->Vec<u8>{
        let mut block : Vec<u8> = input;
        let (nk,nr) = self.bit_type.nk_nr();
        let key = key_exp(self.key.clone(), nk, nr);
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