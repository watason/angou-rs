
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

    let mut rcon : [aesGF;11] = [aesGF::default();11];
    rcon[1] = aesGF{value : 1};
    for i in 1..10{
        rcon[i+1] = rcon[i] * aesGF{value : 2}; 
    }
    let mut rcon = rcon.map(|x|x.value);
    for item in rcon.iter(){
        println!("rcon is {:x}",item);
    }
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

    let mut key128 : [u8;16] = [0;16];
    for (i,item) in key128.iter_mut().enumerate(){
        *item = i as u8;
    }
    let mut key128 = cipher::shift_word(&mut key128);
    println!("after shift word key128 is {:?}",key128);
    let mut key128 = cipher::sub_word(& mut key128);
    println!("after sub word key128 is {:x?}",key128);
  
    let test1 : u32 = 0x12345678;
    let test2 = test1 << 24 | test1 >>8;
    println!("32 bit shift {:x}",test2);
    let test3 = test2.to_be_bytes();
    for t in test3{println!("{:x}",t);}
    // let keys = cipher::key_expansion(&key128, nk, nr, &rcon);
    // println!("{:?}",key);


    let key128 : Vec<u32> = vec![0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c];
    let key_e = cipher::key_exp(key128.clone(), nk, nr);
    // println!("Result: {}", key_e.iter().map(|x| format!("{:02X}", x)).collect::<String>());
    // println!("{:?}",key_e.len());

    let key192 : Vec<u32> = vec![0x8e73b0f7,0xda0e6452,0xc810f32b,0x809079e5,0x62f8ead2,0x522c6b7b];
    let key192_ex = cipher::key_exp(key192, 6, 12);
    //println!("Result: {}", key192_ex.iter().map(|x| format!("{:02X}", x)).collect::<String>());
    //println!("{:?}",key192_ex.len());

    let key256 : Vec<u32> = vec![0x603deb10,0x15ca71be,0x2b73aef0,0x857d7781,0x1f352c07,0x3b6108d7,0x2d9810a3,0x0914dff4];
    let key256_ex = cipher::key_exp(key256, 8, 14);
    //println!("Result: {}", key256_ex.iter().map(|x| format!("{:02X}", x)).collect::<String>());
    //println!("{:?}",key256_ex.len());



    let test_input :[u8;16]= [0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34];
    let cipher_key :[u32;4]=[0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c];
 
    
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
