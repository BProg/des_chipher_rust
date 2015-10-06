#[cfg(test)]
mod main_tests;

const MESS : i64 = 0x0123456789ABCDEF;
const KEY : i64 = 0x133457799BBCDFF1;



fn main() {
    let key_plus = generate_key_plus(KEY);
    let (left, right) = split_key(key_plus, 56);
    let subkey_pairs = create_16_subkeys(left, right);
    let _subkeys_48_bit = convert_pairs_to_encrypted_48_bit_keys(subkey_pairs);

    let message_permutation = initial_permutation_of_64bit_message(MESS);
    let (left_message, right_message) = split_key(message_permutation, 64);
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


pub fn split_key(key : i64, key_len: u8) -> (i64, i64) {
    let half_size = key_len / 2;
    let left_half = (key >> half_size) & bit_pattern_ones(half_size);
    let right_half = key & bit_pattern_ones(half_size);
    (left_half,right_half)
}


const LEFT_SHIFTS : [u8; 16] = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

pub fn create_16_subkeys(left_half: i64, right_half: i64) -> Vec<(i64, i64)> {
    let mut subkeys : Vec<(i64, i64)> = Vec::new();
    subkeys.push((left_half, right_half));
    for idx in 0..16 {
        let next_left = bit_rotate_left(subkeys[idx].0, LEFT_SHIFTS[idx], 28);
        let next_right = bit_rotate_left(subkeys[idx].1, LEFT_SHIFTS[idx], 28);
        subkeys.push((next_left, next_right));
    }
    subkeys.remove(0);
    subkeys
}

pub fn bit_rotate_left(bit_pattern : i64, rol_count : u8, pattern_len: u8) -> i64 {
    let ones_for_rolled_bits = bit_pattern_ones(rol_count) << pattern_len - rol_count;
    let rotated_bits = ((ones_for_rolled_bits) & bit_pattern) >> pattern_len - rol_count;
    ((bit_pattern << rol_count) & bit_pattern_ones(pattern_len)) | rotated_bits
}


pub fn bit_pattern_ones(how_much: u8) -> i64 {
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
    let mut keys_48_bit : Vec<i64> = Vec::new();
    for idx in 0..pairs.len() {
        keys_48_bit.push(key_kn_from_pair(pairs[idx].0, pairs[idx].1));
    }
    keys_48_bit
}



//Step 2: Encode each 64-bit block of data.
const IP : [u8; 64] = [
58, 50,42, 34, 26,18, 10, 2,
60, 52,44, 36, 28,20, 12, 4,
62, 54,46, 38, 30,22, 14, 6,
64, 56,48, 40, 32,24, 16, 8,
57, 49,41, 33, 25,17,  9, 1,
59, 51,43, 35, 27,19, 11, 3,
61, 53,45, 37, 29,21, 13, 5,
63, 55,47, 39, 31,23, 15, 7
];
//b = bit
pub fn initial_permutation_of_64bit_message(message : i64) -> i64 {
    let mut permutation = 0i64;
    for idx in 0..64 {
        let bit_at_index_in_message = (message >> (64 - IP[idx])) & 1;
        permutation = permutation << 1;
        permutation = permutation | bit_at_index_in_message;
    }
    permutation
}
