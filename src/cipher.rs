use super::domain::value_object::aes_gf::aesGF;

pub(crate) trait model{
    fn run(&self,blocks : Vec<u8>)->Vec<u8>;
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