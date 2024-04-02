
use gf::GF256;
use std::ops::*;
use std::fmt;

#[derive(Default,Debug,Clone, Copy)]
struct aesGF{
    value :u8

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
    fn inv(self)->Self{
        let mut ret = self;
        for i in 0..253 {
            ret = ret * self;
        }
        //println!("ret is {}",ret);
        ret
    }

    fn make_sbox(self) -> ([u8;256],[u8;256]){
        let mut ret_sbox : [u8;256] = [0;256];
        let mut ret_inv_sbox : [u8;256] = [0;256];
        let shift = |x: u8,i : u8| x<<i | x >>(8-i);
        for i in 0..255{
            let t = Self{value :i as u8}.inv().value;
            ret_sbox[i] = t ^ shift(t,1) ^ shift(t,2) ^ shift(t,3) ^ shift(t,4) ^ 0x63u8;
            ret_inv_sbox[ret_sbox[i] as usize] = i as u8;
            //println!("{:x}",ret[i]);
        }
        (ret_sbox,ret_inv_sbox)
    }
}
#[derive(Default,Debug)]
enum Type {
    #[default]
    aes128,
    aes192,
    aes256
}
#[derive(Default,Debug)]
struct word{
    value : u32
}
fn kr_combinations(t:Type) -> (u8,u8){
     match t{
        Type::aes128 => (4,10),
        Type::aes192 => (6,12),
        Type::aes256 => (8,14)
    }
}
#[derive(Default,Debug)]
struct Block{
    value : Vec<u8>
}

#[derive(Default,Debug)]
struct Input{
    value : Block
}

#[derive(Default,Debug)]
struct Output{
    value : Block
}


#[derive(Default,Debug)]
struct Cipher{
    t : Type,
    input : Input
}

impl Cipher{
    fn kr_combinations(self)-> (u8,u8){
        kr_combinations(self.t)
    }
    fn make_sbox(self)-> [u8;256]{
        let mut ret : [u8;256] = [0;256];
        let rcon :[gf::GF256;4] = [gf::GF(1<<1),gf::GF(1<<2),gf::GF(1<<3),gf::GF(1<<7)*gf::GF(2)];
        for i in rcon.iter(){
            println!("{:x}",i);
        }
        for i in 0..256 {
            let h : GF256 =gf::GF(i as u8);
            let g : GF256 = h.pow(254);
            let f : GF256 = g + g*gf::GF(2) + g*gf::GF(4)   +  g*gf::GF(8) +  g*gf::GF(16) + gf::GF(0x63);
            println!("{:x>08} {:x} {:b} {:x}",h,g,g,f);
        }

        ret

    }
    
}
fn main() {
    let v : i32 = 32;
    println!("Hello, world! {}",v);
    let t = Block::default();
    let out = Output::default();
    println!("{:?}, {:?}",t,out);
    let testType  = Type::aes128;
    let (Nk,Nr) = kr_combinations(testType);
    println!("{} {}",Nk,Nr);

    let c : Cipher = Default::default();
    println!("{:?}",c);


    let g : GF256 = gf::GF(0x63);
    let h : GF256 = g.pow(254);
    println!("{:o}",h);


    let sbox : [u8;256] = [ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ];
    let mut inv : [u8;256] = [0;256];
    // for (index,item) in sbox.iter().enumerate(){
    //     inv[sbox[index as usize] as usize ] = index as u8;
    // }

    // for (index,item) in inv.iter().enumerate(){
    //    if index%16 ==0 {
    //     println!("");
 
    //   } 
    //     print!("{:x} ,",item)
    // }

    let a : aesGF = aesGF{value : 2};
    let b  = aesGF{value : 2};
    let c = aesGF{value: 0xd4};
    let (mysbox , my_inv_sbox) = a.make_sbox();
    for (index,item) in mysbox.iter().enumerate(){
        if index%16 == 0 && index != 0 {println!();}
        print!("{:>02x},",item);
    }
    println!();
    
    println!();
    for (index,item) in my_inv_sbox.iter().enumerate(){
        if index%16 == 0 && index != 0 {println!();}
        print!("{:>02x},",item);
    }
    println!("{}",a+b);
    println!("{}",a*a);
    //c.makeSbox();


}
