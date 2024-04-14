use std::default;


#[derive(Default,Debug,Clone, Copy)]
pub enum BitType {
    #[default]
    Aes128,
    Aes192,
    Aes256
}

impl BitType {
    pub fn nk_nr(self)->(usize,usize){
        match self{
            BitType::Aes128 => (4,10),
            BitType::Aes192 => (6,12),
            BitType::Aes256 => (8,14)
        }
    }
}

#[derive(Default,Debug,Clone)]
pub enum Mode{
    #[default]
    Ecb,
    Cbc(Vec<u32>)
}

impl Mode{
}
