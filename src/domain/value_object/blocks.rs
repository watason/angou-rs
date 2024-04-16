use super::aes_type;


#[derive(Debug,Default)]
struct Key{
    value : Vec<u32>,
    bit_type : aes_type::BitType,
    mode : aes_type::Mode
}

impl Key{
    
}