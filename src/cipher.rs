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