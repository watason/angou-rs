use std::ops::Add;

use crate::domain::value_object::blocks;

use super::domain::value_object::aes_gf::aesGF;

pub(crate) trait Rayer{
    fn forward(&self,blocks : Vec<u8>)->Vec<u8>;
    fn back(&self,blocks : Vec<u8>)->Vec<u8>;
}
#[derive(Default,Debug)]
struct Cipher{
    inverse : bool,
    input : [u8;16]
}
impl Cipher{

}
struct ShiftRow{}
struct MixCulumn{}
struct SubBytes{}
struct AddRoundKey{}

impl Rayer for ShiftRow{
    fn forward(&self,blocks : Vec<u8>)->Vec<u8> {
        todo!()
    }

    fn back(&self,blocks : Vec<u8>)->Vec<u8> {
        todo!()
    }
}

impl Rayer for MixCulumn{
    fn forward(&self,blocks : Vec<u8>)->Vec<u8> {
        todo!()
    }

    fn back(&self,blocks : Vec<u8>)->Vec<u8> {
        todo!()
    }
}

impl Rayer for SubBytes{
    fn forward(&self,blocks : Vec<u8>)->Vec<u8> {
        todo!()
    }

    fn back(&self,blocks : Vec<u8>)->Vec<u8> {
        todo!()
    }
}
impl Rayer for AddRoundKey{
    fn forward(&self,blocks : Vec<u8>)->Vec<u8> {
        todo!()
    }

    fn back(&self,blocks : Vec<u8>)->Vec<u8> {
        todo!()
    }
}
pub(crate) fn make_sbox() -> ([u8;256],[u8;256]){
    let mut ret_sbox : [u8;256] = [0;256];
    let mut ret_inv_sbox : [u8;256] = [0;256];
    let shift = |x: u8,i : u8| x<<i | x >>(8-i);
    for i in 0..255{
        let t = aesGF{value :i as u8}.inv().value;
        ret_sbox[i] = t ^ shift(t,1) ^ shift(t,2) ^ shift(t,3) ^ shift(t,4) ^ 0x63u8;
        ret_inv_sbox[ret_sbox[i] as usize] = i as u8;
        //println!("{:x}",ret[i]);
    }
    (ret_sbox,ret_inv_sbox)
}

pub fn shift_row(blocks : [u8;16],inverse : bool) -> [u8;16]{
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
    let mut blocks = blocks;
    for i in 0..4 {
        let index = 4*i; 
        println!("{}",index);
        let mut sep = &mut blocks[(index)..(index+4)];
        sep.rotate_left(if !inverse {i}else{4-i});
        println!("{:?}",sep);
    }
    blocks
}


pub fn sub_bytes(blocks : [u8;16],inverse : bool) ->[u8;16]{
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

pub fn mix_column(blocks: [aesGF;16],inverse : bool)->[aesGF;16]{
    let mut ret :[aesGF;16] = [aesGF::default();16];
    for i in 0..4{
        if !inverse {
        ret[i] = aesGF{value : 2}*blocks[i] + aesGF{value :3}*blocks[4+i] +   blocks[8+i] + blocks[12+i];
        ret[i +4] =   blocks[i] + aesGF{value : 2}*blocks[4+i] + aesGF{value :3}*blocks[8+i] + blocks[12+i];
        ret[i +8] =   blocks[i] +   blocks[4+i] + aesGF{value : 2}*blocks[8+i] + aesGF{value :3}*blocks[12+i];
        ret[i +12] = aesGF{value :3}*blocks[i] +   blocks[4+i] +   blocks[8+i] + aesGF{value : 2}*blocks[12+i];
        }else{

        ret[i] = aesGF{value : 0x0e}* blocks[i] + aesGF{value :0x0b}* blocks[i +4] + aesGF{value :0x0d}* blocks[i + 8] + aesGF{value :0x09}* blocks[i + 12];
        ret[i + 4] = aesGF{value :0x09}* blocks[i] + aesGF{value : 0x0e}* blocks[i+4] +aesGF{value :0x0b}* blocks[i +8] + aesGF{value :0x0d}* blocks[i + 12];
        ret[i + 8] = aesGF{value :0x0d}* blocks[i] + aesGF{value :0x09}* blocks[i+4] +  aesGF{value : 0x0e}* blocks[i + 8] + aesGF{value :0x0b}* blocks[i +12];
        ret[i + 12] =aesGF{value :0x0b}* blocks[i] +aesGF{value :0x0d}* blocks[i +4] + aesGF{value :0x09}* blocks[i + 8] +  aesGF{value : 0x0e}* blocks[i+12]; 
        }
    }
    ret
}

pub fn add_round_key(blocks: [aesGF;16],key : &[u8],inverse : bool)->[aesGF;16]{
    let mut ret = blocks;
    for i in 0..4{
        for j in 0..4{
            ret[4*i +j] = blocks[4*i +j] + aesGF{value : key[i]};
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

// pub fn key_expansion(keys : &[u8],nk : u8,nr : u8,rcon : &[u8])->Box<[u8]>{
//     let round_count = ((nr as usize) + 1) * 16;
//     let word :usize = 16;
//     let key_num = nk as usize*4;
//     let mut ret :Box<[u8]> = Box::new([0;176]);
//     for i in (0..round_count).step_by(4){
//         if i/key_num == 0{
//             for j in 0..4{
//                 ret[4*i+j] = keys[4*i+j];
//             }
//         }else {
//             let mut key = &mut ret[(i-4)..i];
//             let pre = &ret[(i-key_num)..(i-key_num+3)];
//             if i%key_num == 0{
//                 let mut w = sub_word(key);
//                 let mut w = shift_word(w);
                
//                 ret[4*i ] ^= w[0] ;
//                 ret[4*i +1] ^= w[1] ;
//                 ret[4*i +2] ^= w[2] ;
//                 ret[4*i +3] ^= w[3] ^ rcon[i/16];
//             }

//             ret[4*i ] ^= pre[0] ;
//             ret[4*i +1] ^= pre[1] ;
//             ret[4*i +2] ^= pre[2] ;
//             ret[4*i +3] ^= pre[3] ;

//         }
//     }
//     ret
// }