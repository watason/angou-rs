
mod domain;
mod cipher;
use gf::GF256;
use domain::value_object::aes_gf::aesGF;
use domain::value_object::aes_type;


// impl Cipher{
//     fn make_sbox(self)-> [u8;256]{
//         let mut ret : [u8;256] = [0;256];
//         let rcon :[gf::GF256;4] = [gf::GF(1<<1),gf::GF(1<<2),gf::GF(1<<3),gf::GF(1<<7)*gf::GF(2)];
//         for i in rcon.iter(){
//             println!("{:x}",i);
//         }
//         for i in 0..256 {
//             let h : GF256 =gf::GF(i as u8);
//             let g : GF256 = h.pow(254);
//             let f : GF256 = g + g*gf::GF(2) + g*gf::GF(4)   +  g*gf::GF(8) +  g*gf::GF(16) + gf::GF(0x63);
//             println!("{:x>08} {:x} {:b} {:x}",h,g,g,f);
//         }

//         ret

//     }
    
// }
fn main() {
    let v : i32 = 32;
    println!("Hello, world! {}",v);


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
    let (mysbox , my_inv_sbox) = cipher::make_sbox();
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
