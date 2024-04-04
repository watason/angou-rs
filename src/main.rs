
mod domain;
mod cipher;
use gf::GF256;
use domain::value_object::aes_gf::aesGF;
use domain::value_object::aes_type;
use cipher::*;

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

    let (aes_type,nk,nr) = aes_type::aes_tuple(0).unwrap();

    let key :[u8;32] = [1;32];
    let mut input : [u8;16] = [0;16];

    for i in 0..16 {
        input[i/4 + 4*(i%4)] = i as u8;
    }
    let mut input2 = input.clone();
    println!("{:?}",input); 
    let input = cipher::shift_row(input, false);
    
    println!(" after shift row {:?}",input);
    let input = cipher::shift_row(input, true);
    
    println!(" after inv shift row {:?}",input); 
    let input = cipher::sub_bytes(input, false);
    println!("after subbyte {:?}",input); 
    let input  = cipher::sub_bytes(input, true);
    println!("after invsubbyte {:?}",input);
    

    let mut input_gf : [aesGF;16] = [aesGF::default();16];
    input_gf[0]=aesGF{value:0xd4};
    input_gf[4]=aesGF{value:0xbf};
    input_gf[8]=aesGF{value:0x5d};
    input_gf[12]=aesGF{value:0x30};
    let input = cipher::mix_column(input_gf, false);
    
    
    println!("after mixculum {}",input[0]);
    println!("after mixculum {}",input[4]);    
    println!("after mixculum {}",input[8]);
    println!("after mixculum {}",input[12]);
    

    println!("after mixculum {:?}",input);
    
    let input = cipher::mix_column(input, true);
    println!("after invmixculum {}",input[0]);
    println!("after invmixculum {}",input[4]);    
    println!("after mixculum {}",input[8]);
    println!("after mixculum {}",input[12]);
    

    println!("after inv mixculum {:?}",input);


    let input = cipher::add_round_key(input, &key, false);
    println!("after add round key {:?}",input);

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
