use std::ops::*;
use std::fmt;
use std::mem;

#[derive(Default,Debug,Clone, Copy)]
pub struct aesGF{
    pub value :u8

}

impl Add for aesGF{
    type Output = Self;
    fn add(self,rhs : Self)-> Self{
        Self { value: (self.value ^ rhs.value) }
    }
}

impl Mul for aesGF{
    type Output = Self;
    
    fn mul(self, rhs: Self) -> Self::Output {

        let mut ret : u8 = 0;
        let mut n : u8  = rhs.value;
        let mut a : u8 = self.value;
        while n > 0{
            if n&1 == 1 {
                ret = ret ^ a;
            }
            a = (a << 1) ^ (if a&0x80 == 0x80 {0x1b}else{0});
            //println!("{:>08b} {} {:>08b}",ret,n,a);
            
            n >>= 1;
        }
        Self{value :ret}
    }
    
}
impl fmt::Display for aesGF{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.value)
    }
}

impl aesGF{
    pub fn inv(self)->Self{
        let mut ret = self;
        for i in 0..253 {
            ret = ret * self;
        }
        //println!("ret is {}",ret);
        ret
    }


}