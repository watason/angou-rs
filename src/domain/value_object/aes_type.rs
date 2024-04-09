
#[derive(Default,Debug,Clone, Copy)]
pub enum Type {
    #[default]
    aes128,
    aes192,
    aes256
}

impl Type {
    pub fn nk_nr(self)->(u8,u8){
        match self{
            Type::aes128 => (4,10),
            Type::aes192 => (6,12),
            Type::aes256 => (8,14)
        }
    }
}