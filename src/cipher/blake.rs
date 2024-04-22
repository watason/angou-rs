
#[derive(Debug)]
struct Blake2{
    h : [u64;8]
}

#[derive(Debug,Default,Clone)]
struct Key{
    value : Vec<u8>
}
impl Blake2 {
    //IV
    const IV : [u64;8] = [
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
    ];

    const SIGMA : [u8;256] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    ]; 

    fn new()->Self{
        Self{h:blake2b_iv}
    } 

    fn rotate(x : u64,y : u64)->u64{
        x >> y | x << (64 - y)
    }

    pub fn hash(&self,m:Vec<u8>,nn : u8,key : Key){
        let m = m;
        let message_len : u128 = m.len();
        let key = key;
        let nn : u64 = nn;
        let key_length : u64 = key.value.len();

        let mut h = blake2b_iv.to_vec();
        let mut cbyte_compress : u128 = 0;
        let mut cbyte_remain = message_len;

        if key_length > 0{
            m.extend(padding(key,128));
            cbyte_remain+=128;
        }

        while cbyte_remain > 128 {
            let chunk = &m[cbyte_compress..(cbyte_compress + 128)].into();
            cbyte_compress += 128;
            cbyte_remain -= 128;
            h = self.compress(h,chunk,cbyte_compress,false);
        }

        let chunk = &m[cbyte_compress..(cbyte_compress + 128)].into();
        cbyte_compress += 128;
        cbyte_remain -= 128;

        h= self.comress(h,chunk,cbyte_compress,true);

        h[0..nn]
    }

    fn compress(&self,h:Vec<u8>,chunk:&[u8],cbyte_compress: u128,final : bool)->Vec<u8>{
        let mut v : Vec<u8> = h;
        v.extend(self.iv);

        v[12] ^= u64::try_from(t).ok();
        v[13] ^= u64::try_from(t >> 64).ok();

        if final{
            v[14] ^=  0xFFFFFFFFFFFFFFFF;
        }

        let m : Vec<u8> = chunk.to_vec();

        for i in 0..11{
            let imod = (i % 10)*16;
            let s = &Blake2::SIGMA[imod..(imod+16)].to_vec();

        }

        h.iter().enumerate().map(|(i,x)|{
            x ^ v[i] ^ v[i+8]
        }).collect::<Vec<u8>>()
    }

    fn g(&self){
        
    }

}