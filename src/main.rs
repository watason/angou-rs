
mod domain;
mod cipher;
use gf::GF256;
use domain::value_object::aes_gf::aesGF;
use domain::value_object::aes_type;
use cipher::*;

use crate::domain::value_object;
use crate::domain::value_object::aes_type::*;

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
    let (nk,nr) = BitType::Aes128.nk_nr();

    let key :[u8;32] = [1;32];
    let mut input  = vec![0;16];

    for i in 0..16 {
        input[i] = i as u8;
    }
    let mut input2 = input.clone();
    println!("{:?}",input); 
    let input = cipher::shift_row(input, false);
    for (index,item) in input.iter().enumerate(){
        if index%4 == 0 && index != 0 {println!();}
        print!("{:>02},",item);
    }
    // println!(" after shift row {:?}",input);
    // let input = cipher::shift_row(input, true);
    
    println!(" after inv shift row {:?}",input); 
    let input = cipher::sub_bytes(input, false);
    println!("after subbyte "); 
    // let input  = cipher::sub_bytes(input, true);
    // println!("after invsubbyte {:?}",input);
    for (index,item) in input.iter().enumerate(){
        if index%4 == 0 && index != 0 {println!();}
        print!("{:>02x},",item);
    }
    println!();


    let input = cipher::mix_column(input, false);
    
    
    println!("after mixculum ");
    for (index,item) in input.iter().enumerate(){
        if index%4 == 0 && index != 0 {println!();}
        print!("{:>02},",item);
    }
    
    let input = cipher::mix_column(input, true);
    println!("after invmixculum ");
    for (index,item) in input.iter().enumerate(){
        if index%4 == 0 && index != 0 {println!();}
        print!("{:>02},",item);
    }

    let input_add_round_key  =  vec![0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34];
    let add_cipher_key :Vec<u32> = vec![0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c];
    let key_expand = cipher::key_exp(add_cipher_key, nk, nr);
    for item in key_expand.iter().enumerate(){
        println!("key exp round {} is {:x} ",item.0,item.1);
    }
    let input = cipher::add_round_key(input_add_round_key, key_expand[0..4].to_vec(), false);
    println!("after add round key0  Result: {}", input.iter().map(|x| format!("{:02X}", x)).collect::<String>());
    
    println!("Result: {}", input.iter().map(|x| format!("{:02X}", x)).collect::<String>());

    let input = cipher::sub_bytes(input,false);
    println!("after subbyte Result: {}", input.iter().map(|x| format!("{:02X}", x)).collect::<String>());

    let input = cipher::shift_row(input, false);
    println!("after shiftrow Result: {}", input.iter().map(|x| format!("{:02X}", x)).collect::<String>());

    let input =cipher::mix_column(input, false);
    println!("after mixcolumn Result: {}", input.iter().map(|x| format!("{:02X}", x)).collect::<String>());

    let input = cipher::add_round_key(input, key_expand[4..8].to_vec(), false);
    println!("after add round key1  Result: {}", input.iter().map(|x| format!("{:02X}", x)).collect::<String>());



    // let s = "hello worldaaaaa".as_bytes().to_vec();
    // println!("hello world byte is {:?}",s);
    // let input = cipher::cipher(s, key.clone(), false);
    // println!("after hello cipher  Result: {}", input.iter().map(|x| format!("{:02X}", x)).collect::<String>());
    // let input = cipher::cipher(input, key.clone(), true);
    // let str = std::str::from_utf8(&input).unwrap();
    // println!("text is {}",str);


    // let ss  ="hello world".as_bytes().to_vec();
    // let ss = cipher::padding_pkcs_7(ss);    
    // //let ss = std::str::from_utf8(&ss).unwrap();
    // println!("paddiing text is {:?}",ss);


    
    
    //openssl
    //encode 
    //key= 2b7e151628aed2a6abf7158809cf4f3c
    //ciphertext=53616c7465645f5fa042fac4400738e8fa675d31fe226edd81cc54fddb5127bc5954ad474733fbf63b9e1a5187655e93
    let input = hex::decode("53616c7465645f5fa042fac4400738e8fa675d31fe226edd81cc54fddb5127bc5954ad474733fbf63b9e1a5187655e93").expect("error string to hex");
    let key = vec![0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c];
    //let input = cipher::cipher(input, key.clone(), false);
    //println!("ciphertxt  test4  Result: {}", input.iter().map(|x| format!("{:02X}", x)).collect::<String>());
    let input = cipher::cipher(input, key.clone(), true);
    println!("after ciphertxt test4  Result: {}", input.iter().map(|x| format!("{:02X}", x)).collect::<String>());

    
    
    
    
    let input = hex::decode("ae2d8a571e03ac9c9eb76fac45af8e51").expect("test ae2d error");
    let key = vec![0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c];
    let bit_type = aes_type::BitType::Aes128;
    let mode = aes_type::Mode::Ecb;
    let aes : AES = AES::new(key.clone(),bit_type,mode);
    let input = aes.encrypt(input);
    println!("{:x?}",input);
    // let keys = cipher::key_expansion(&key128, nk, nr, &rcon);
    // println!("{:?}",key);


    //let key128 : Vec<u32> = vec![0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c];
    //let key_e = cipher::key_exp(key128.clone(), nk, nr);
    // println!("Result: {}", key_e.iter().map(|x| format!("{:02X}", x)).collect::<String>());
    // println!("{:?}",key_e.len());

    //let key192 : Vec<u32> = vec![0x8e73b0f7,0xda0e6452,0xc810f32b,0x809079e5,0x62f8ead2,0x522c6b7b];
    //let key192_ex = cipher::key_exp(key192, 6, 12);
    //println!("Result: {}", key192_ex.iter().map(|x| format!("{:02X}", x)).collect::<String>());
    //println!("{:?}",key192_ex.len());

    //let key256 : Vec<u32> = vec![0x603deb10,0x15ca71be,0x2b73aef0,0x857d7781,0x1f352c07,0x3b6108d7,0x2d9810a3,0x0914dff4];
    //let key256_ex = cipher::key_exp(key256, 8, 14);
    //println!("Result: {}", key256_ex.iter().map(|x| format!("{:02X}", x)).collect::<String>());
    //println!("{:?}",key256_ex.len());



    let test_input :[u8;16]= [0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34];
    let cipher_key :[u32;4]=[0x2b7e1516,0x28aed2a6,0xabf71588,0x09cf4f3c];
 
    let t = value_object::aes_type::BitType::Aes128;
    let (nk,nr) = t.nk_nr();
    println!("type is {} {}",nk,nr);

}
