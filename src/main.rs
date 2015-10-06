#[cfg(test)]
mod main_tests;

//const MESS : i64 = 0x0123456789ABCDEF;
const KEY : i64 = 0x133457799BBCDFF1;



fn main() {
    let key_plus = generate_key_plus(KEY);
    let (left, right) = split_key(key_plus, 56);
    let subkeys = create_16_subkeys(left, right);
    for idx in 0..subkeys.len() {
        println!("[{0}]{1:b}\n[{0}]{2:b}\n\n",idx, subkeys[idx].0, subkeys[idx].1);
    }
    //println!("{:b}\n{:b}", left, right);
}


//Step 1: Create 16 subkeys, each of which is 48-bits long.
const PC1 : [u8; 56] =
[57, 49, 41, 33, 25, 17, 9, 1,
58, 50, 42, 34, 26, 18, 10, 2,
59, 51, 43, 35, 27, 19, 11, 3,
60, 52, 44, 36, 63, 55, 47, 39,
31, 23, 15, 7, 62, 54, 46, 38,
30, 22, 14, 6, 61, 53, 45, 37,
29, 21, 13, 5, 28, 20, 12, 4];


pub fn generate_key_plus(key: i64) -> i64 {
    let mut key_plus : i64 = 0;
    for idx in 0..56 {
        let bit_to_add = key >> (64 - PC1[idx]) & 1;
        key_plus = key_plus << 1;
        key_plus = key_plus | bit_to_add;
    }
    key_plus
}


pub fn split_key(key : i64, key_len: i8) -> (i64, i64) {
    let left_half = key >> key_len / 2;
    let right_half = (key << 64 - key_len + key_len / 2) >> 64 - key_len + key_len / 2;
    (left_half,right_half)
}


const LEFT_SHIFTS : [u8; 16] = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

pub fn create_16_subkeys(left_half: i64, right_half: i64) -> Vec<(i64, i64)> {
    let mut subkeys : Vec<(i64, i64)> = Vec::new();
    subkeys.push((left_half, right_half));
    for idx in 0..16 {
        let next_left = bit_rotate_left(subkeys[idx].0, LEFT_SHIFTS[idx]);
        let next_right = bit_rotate_left(subkeys[idx].1, LEFT_SHIFTS[idx]);
        subkeys.push((next_left, next_right));
    }
    subkeys.remove(0);
    subkeys
}

pub fn bit_rotate_left(bit_array : i64, rol_count : u8) -> i64 {
    let rotated_bit = ((bit_pattern_containing_ones(rol_count) << 28 - rol_count) & bit_array) >> 28 - rol_count;
    ((bit_array << rol_count) & 0xffff_fff) | rotated_bit
}


pub fn bit_pattern_containing_ones(how_much: u8) -> i64 {
    ((2u64).pow(how_much as u32) - 1) as i64
}


const PC2 : [u8; 48] =
[14, 17, 11, 24, 1, 5,
  3, 28, 15, 6, 21, 10,
 23, 19, 12, 4, 26, 8,
 16, 7, 27, 20, 13, 2,
 41, 52, 31, 37, 47, 55,
 30, 40, 51, 45, 33, 48,
 44, 49, 39, 56, 34, 53,
 46, 42, 50, 36, 29, 32];


pub fn key_kn_from_pair(left: i64, right: i64) -> i64 {
    let combined = ((left << 28) | right) << 8;
    let mut encrypted_key = 0i64;
    for idx in 0..48 {
        let combined_bit_at_position = (combined >> (64 - PC2[idx])) & 1;
        encrypted_key = encrypted_key << 1;
        encrypted_key = encrypted_key | combined_bit_at_position;
    }
    encrypted_key
}


pub fn convert_pairs_to_encrypted_48_bit_keys(pairs: Vec<(i64, i64)>) -> Vec<i64> {
    Vec::new()
}
