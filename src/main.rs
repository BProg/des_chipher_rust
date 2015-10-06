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


fn generate_key_plus(key: i64) -> i64 {
    let mut key_plus : i64 = 0;
    for idx in 0..56 {
        let bit_to_add = key >> (64 - PC1[idx]) & 1;
        key_plus = key_plus << 1;
        key_plus = key_plus | bit_to_add;
    }
    key_plus
}


fn split_key(key : i64, key_len: u8) -> (i64, i64) {
    let half_size = key_len / 2;
    let left_half = (key >> half_size) & bit_pattern_ones(half_size);
    let right_half = key & bit_pattern_ones(half_size);
    (left_half,right_half)
}


const LEFT_SHIFTS : [u8; 16] = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

fn create_16_subkeys(left_half: i64, right_half: i64) -> Vec<(i64, i64)> {
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

fn bit_rotate_left(bit_pattern : i64, rol_count : u8, pattern_len: u8) -> i64 {
    let ones_for_rolled_bits = bit_pattern_ones(rol_count) << pattern_len - rol_count;
    let rotated_bits = ((ones_for_rolled_bits) & bit_pattern) >> pattern_len - rol_count;
    ((bit_pattern << rol_count) & bit_pattern_ones(pattern_len)) | rotated_bits
}


fn bit_pattern_ones(how_much: u8) -> i64 {
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


fn key_kn_from_pair(left: i64, right: i64) -> i64 {
    let combined = ((left << 28) | right) << 8;
    let mut encrypted_key = 0i64;
    for idx in 0..48 {
        let combined_bit_at_position = (combined >> (64 - PC2[idx])) & 1;
        encrypted_key = encrypted_key << 1;
        encrypted_key = encrypted_key | combined_bit_at_position;
    }
    encrypted_key
}


fn convert_pairs_to_encrypted_48_bit_keys(pairs: Vec<(i64, i64)>) -> Vec<i64> {
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
fn initial_permutation_of_64bit_message(message : i64) -> i64 {
    let mut permutation = 0i64;
    for idx in 0..64 {
        let bit_at_index_in_message = (message >> (64 - IP[idx])) & 1;
        permutation = permutation << 1;
        permutation = permutation | bit_at_index_in_message;
    }
    permutation
}




//tests
#[cfg(test)]
#[test]
fn rotatig_bit_with_1_on_firstbit() {
    let bit_to_rotate : i64 = 0b1111000011110000111100001111;
    assert_eq!(0b1110000111100001111000011111, bit_rotate_left(bit_to_rotate, 1, 28));
}


#[cfg(test)]
#[test]
fn rotatig_bit_with_2_positions() {
    let bit_to_rotate : i64 = 0b1111_0000_1111_0000_1111_0000_1111;
    assert_eq!(0b1100_0011_1100_0011_1100_0011_1111, bit_rotate_left(bit_to_rotate, 2, 28));
}


#[cfg(test)]
#[test]
fn ones_for_2_is_11() {
    assert_eq!(0b11, bit_pattern_ones(2));
}


#[cfg(test)]
#[test]
fn creating_vector_with_keys_returns_correct_subkeys() {
    let subkeys = create_16_subkeys(0b1111000011001100101010101111, 0b0101010101100110011110001111);
    assert_eq!(16, subkeys.len());
    //1
    assert_eq!(0b1110000110011001010101011111, subkeys[0].0);
    assert_eq!(0b1010101011001100111100011110, subkeys[0].1);
    //2
    assert_eq!(0b1100001100110010101010111111, subkeys[1].0);
    assert_eq!(0b0101010110011001111000111101, subkeys[1].1);
    //3
    assert_eq!(0b0000110011001010101011111111, subkeys[2].0);
    assert_eq!(0b0101011001100111100011110101, subkeys[2].1);
    //4
    assert_eq!(0b0011001100101010101111111100, subkeys[3].0);
    assert_eq!(0b0101100110011110001111010101, subkeys[3].1);
    //5
    assert_eq!(0b1100110010101010111111110000, subkeys[4].0);
    assert_eq!(0b0110011001111000111101010101, subkeys[4].1);
    //6
    assert_eq!(0b0011001010101011111111000011, subkeys[5].0);
    assert_eq!(0b1001100111100011110101010101, subkeys[5].1);
    //7
    assert_eq!(0b1100101010101111111100001100, subkeys[6].0);
    assert_eq!(0b0110011110001111010101010110, subkeys[6].1);
    //8
    assert_eq!(0b0010101010111111110000110011, subkeys[7].0);
    assert_eq!(0b1001111000111101010101011001, subkeys[7].1);
    //9
    assert_eq!(0b0101010101111111100001100110, subkeys[8].0);
    assert_eq!(0b0011110001111010101010110011, subkeys[8].1);
    //10
    assert_eq!(0b0101010111111110000110011001, subkeys[9].0);
    assert_eq!(0b1111000111101010101011001100, subkeys[9].1);
    //11
    assert_eq!(0b0101011111111000011001100101, subkeys[10].0);
    assert_eq!(0b1100011110101010101100110011, subkeys[10].1);
    //12
    assert_eq!(0b0101111111100001100110010101, subkeys[11].0);
    assert_eq!(0b0001111010101010110011001111, subkeys[11].1);
    //13
    assert_eq!(0b0111111110000110011001010101, subkeys[12].0);
    assert_eq!(0b0111101010101011001100111100, subkeys[12].1);
    //14
    assert_eq!(0b1111111000011001100101010101, subkeys[13].0);
    assert_eq!(0b1110101010101100110011110001, subkeys[13].1);
    //15
    assert_eq!(0b1111100001100110010101010111, subkeys[14].0);
    assert_eq!(0b1010101010110011001111000111, subkeys[14].1);
    //16
    assert_eq!(0b1111000011001100101010101111, subkeys[15].0);
    assert_eq!(0b0101010101100110011110001111, subkeys[15].1);

}


#[cfg(test)]
#[test]
fn test_spliting_a_56_bit_key_into_2_x_28_keys() {
    let original_key = 0b11110000110011001010101011110101010101100110011110001111;
    let expected_left = 0b1111000011001100101010101111;
    let expected_right = 0b0101010101100110011110001111;
    assert_eq!((expected_left, expected_right), split_key(original_key, 56));
}


#[cfg(test)]
#[test]
fn generate_key_plus_based_on_pc1_table() {
    let key = 0b0001001100110100010101110111100110011011101111001101111111110001;
    let key_plus = 0b11110000110011001010101011110101010101100110011110001111;
    assert_eq!(key_plus, generate_key_plus(key));
}


#[cfg(test)]
#[test]
fn creating_key_based_on_pairs_and_PC2_table() {
    let left = 0b1110000110011001010101011111;
    let right = 0b1010101011001100111100011110;
    let expected_key = 0b000110110000001011101111111111000111000001110010;
    assert_eq!(expected_key, key_kn_from_pair(left, right));
}


#[cfg(test)]
#[test]
fn creating_48_bit_key_based_on_maximum_pairs() {
    let left = 0b1111_1111_1111_1111_1111_1111_1111;
    let right = 0b1111_1111_1111_1111_1111_1111_1111;
    let expected = 0b1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111;
    assert_eq!(expected, key_kn_from_pair(left, right));
}


#[cfg(test)]
#[test]
fn get_48_bit_keys_from_array_of_28_bit_pairs() {
    let pairs_28_bit = vec![(0b1110000110011001010101011111,0b1010101011001100111100011110),
    (0b1100001100110010101010111111,0b0101010110011001111000111101),
    (0b0000110011001010101011111111,0b0101011001100111100011110101),
    (0b0011001100101010101111111100,0b0101100110011110001111010101),

    (0b1100110010101010111111110000,0b0110011001111000111101010101),
    (0b0011001010101011111111000011,0b1001100111100011110101010101),
    (0b1100101010101111111100001100,0b0110011110001111010101010110),
    (0b0010101010111111110000110011,0b1001111000111101010101011001)];

    let expected = vec![0b000110110000001011101111111111000111000001110010,
    0b011110011010111011011001110110111100100111100101,
    0b010101011111110010001010010000101100111110011001,
    0b011100101010110111010110110110110011010100011101,
    0b011111001110110000000111111010110101001110101000,
    0b011000111010010100111110010100000111101100101111,
    0b111011001000010010110111111101100001100010111100,
    0b111101111000101000111010110000010011101111111011];

    assert_eq!(expected, convert_pairs_to_encrypted_48_bit_keys(pairs_28_bit));
}


#[cfg(test)]
#[test]
fn permutation_of_64bit_integer_gives_58_bit() {
    let message_64bit = 0x123456789abcdef;
    let intial_permutation = 0xcc00ccfff0aaf0aa;
    assert_eq!(intial_permutation, initial_permutation_of_64bit_message(message_64bit));
}


#[cfg(test)]
#[test]
fn splitting_key_of_64_bit_into_32_bit_pair() {
    let key =  0xcc00ccfff0aaf0aa;
    let left = 0xcc00ccffi64;
    let right = 0xf0aaf0aai64;
    assert_eq!((left, right), split_key(key, 64));
}
