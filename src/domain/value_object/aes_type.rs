
#[derive(Default,Debug,Clone, Copy)]
pub enum Type {
    #[default]
    Aes128,
    Aes192,
    Aes256
}

impl Type {
    pub fn nk_nr(self)->(u8,u8){
        match self{
            Type::Aes128 => (4,10),
            Type::Aes192 => (6,12),
            Type::Aes256 => (8,14)
        }
    }
}