
#[derive(Default,Debug,Clone, Copy)]
pub enum Type {
    #[default]
    aes128,
    aes192,
    aes256
}

#[derive(Default,Debug,Copy,Clone)]
pub struct aes_type(Type,u8,u8);

pub fn type_tuple(num : u8)-> Result<(Type,u8,u8),String>{
    match num {
        0 => Ok((Type::aes128,4,10)),
        1 => Ok((Type::aes192,6,12)),
        2 => Ok((Type::aes256,8,14)),
        _ => Err("error".to_string())
    }
}
