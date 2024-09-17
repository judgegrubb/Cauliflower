
pub struct Md5;

struct Md5Internal {
    pub A: u32,
    pub B: u32,
    pub C: u32,
    pub D: u32,
}

const s: [u32; 64] = [ 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
                       5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
                       4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
                       6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 ];

const K: [u32; 64] = [ 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                       0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                       0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                       0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                       0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                       0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                       0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                       0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                       0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                       0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                       0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                       0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                       0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                       0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                       0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                       0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 ];

/// Implementation of operations on an Md5 value
/// including AND, OR, XOR, NOT
impl Md5 {
    /// message string to message bytes
    /// call other hash function
    pub fn hash_string(&self, message: &str) -> String {
        let mut hash_string = "".to_string();
        for byte in self.hash(message.as_bytes()) {
            hash_string.push_str(format!("{:02x}", byte).as_str());
        }
        hash_string
    }
    
    /// create new md5 hash
    pub fn new() -> Md5 {
        Md5
    }

    /// message bytes -> padded message
    /// call hash_padded
    pub fn hash(&self, message: &[u8]) -> Vec<u8> {
        let mut message_vec = message.to_vec();

        message_vec.push(0x80);

        while message_vec.len() % 64 != 56 {
            message_vec.push(0x00);
        }

        // need to push on 64 bits / 8 bytes of length data
        // original length in bits mod 2^64
        let len_in_bits: u64 = (message.len() as u64).wrapping_mul(8);

        for hex in len_in_bits.to_le_bytes() {
            message_vec.push(hex);
        }

        let mut message_32bit_vec = Vec::new();

        let mut iter = message_vec.chunks_exact(4);
        
        while let Some(bytes) = iter.next() {
            message_32bit_vec.push(u32::from_le_bytes(bytes.try_into().expect("slice with incorrect length")));
        }
        
        Self::hash_padded(message_32bit_vec)
    } 
    
    /// given padded string
    /// which is series of 512 bytes
    /// or 16 32bit values
    /// for each 512 bit chunk
    /// call our process function 
    fn hash_padded(message: Vec<u32>) -> Vec<u8> {
        let mut md5Init = Md5Internal {
            A: 0x67452301,
            B: 0xefcdab89,
            C: 0x98badcfe,
            D: 0x10325476,
        };

        let mut iter = message.chunks_exact(16);

        while let Some(chunk) = iter.next() {
            Self::process(&mut md5Init, chunk);
        }

        let mut hash_bytes = md5Init.A.to_le_bytes().to_vec();
        hash_bytes.extend(md5Init.B.to_le_bytes());
        hash_bytes.extend(md5Init.C.to_le_bytes());
        hash_bytes.extend(md5Init.D.to_le_bytes());
        hash_bytes
    }
  
    fn process(state: &mut Md5Internal, chunk: &[u32]) {
        let mut A = state.A;
        let mut B = state.B;
        let mut C = state.C;
        let mut D = state.D;

        println!("A={:x}, B={:x}, C={:x}, D={:x}", A, B, C, D);

        for i in 0..64 {
            let (mut F, g) = match i {
                0 ..=15 => ( (B & C) | ((!B) & D),    i             ),
                16..=31 => ( (D & B) | ((!D) & C), (5*i + 1) % 16 ),
                32..=47 => ( B ^ C ^ D,            (3*i + 5) % 16 ),
                48..=63 => ( C ^ (B | (!D)),       (7*i)     % 16 ),
                   _    => panic!("should never reach here"),
            };
            F = F.wrapping_add(A).wrapping_add(K[i]).wrapping_add(chunk[g]);
            A = D;
            D = C;
            C = B;
            B = B.wrapping_add(F.rotate_left(s[i]));
            println!("A={:x}, B={:x}, C={:x}, D={:x}", A, B, C, D); 
        }
        state.A = state.A.wrapping_add(A);
        state.B = state.B.wrapping_add(B);
        state.C = state.C.wrapping_add(C);
        state.D = state.D.wrapping_add(D);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        let hash = Md5::new();
        assert_eq!("d41d8cd98f00b204e9800998ecf8427e",
                   hash.hash_string(""));
        assert_eq!("c4ca4238a0b923820dcc509a6f75849b",
                   hash.hash_string("1"));
        assert_eq!("23db6982caef9e9152f1a5b2589e6ca3",
                   hash.hash_string("They are deterministic"));
        assert_eq!("9e107d9d372bb6826bd81d3542a419d6",
                   hash.hash_string("The quick brown fox jumps over the lazy dog"));
        assert_eq!("e4d909c290d0fb1ca068ffaddf22cbd0",
                   hash.hash_string("The quick brown fox jumps over the lazy dog."));
    }
}
