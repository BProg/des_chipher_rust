const MESS : i64 = 0x0123456789ABCDEF;
const KEY : i64 = 0x133457799BBCDFF1;



fn main() {

    let key_plus = generate_key_plus(KEY);
    let (left, right) = split_key(key_plus, 56);
    let subkey_pairs = create_16_pairs_blocks_32bit(left, right);
    let subkeys_48_bit = convert_pairs_to_encrypted_48_bit_keys(&subkey_pairs);

    let message_permutation = initial_permutation_of_64bit_message(MESS);
    let (left_message, right_message) = split_key(message_permutation, 64);
    let last_pair = generate_last_pair_of_32bit_blocks(left_message,
         right_message,
          &subkeys_48_bit);
    let encrypted_message = last_permutation_with_ip_table(last_pair);
    println!("{:x}", encrypted_message);
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

fn create_16_pairs_blocks_32bit(left_half: i64, right_half: i64) -> Vec<(i64, i64)> {
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


fn convert_pairs_to_encrypted_48_bit_keys(pairs: &Vec<(i64, i64)>) -> Vec<i64> {
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


const E_TABLE : [u8; 48] = [
32,  1, 2,  3,  4, 5,
 4,  5, 6,  7,  8, 9,
 8,  9,10, 11, 12,13,
 12, 13,14, 15, 16,17,
 16, 17,18, 19, 20,21,
 20, 21,22, 23, 24,25,
 24, 25,26, 27, 28,29,
 28, 29,30, 31, 32, 1
];


fn encode_function(block_32bit: i64, block_48bit: i64) -> i64 {
    let expanded_block = expand_32bit_block_to_48bit_block_using_e_table(block_32bit);
    let xored = block_48bit ^ expanded_block;
    let shrinked_xor = shrink_48bit_block_to_32bit_block_with_s_tables(xored);
    permutate_block_32bit_with_p_table(shrinked_xor)
}


fn expand_32bit_block_to_48bit_block_using_e_table(block : i64) -> i64 {
    let mut expanded = 0i64;
    for idx in 0..48 {
        let bit_at_index = (block >> (32 - E_TABLE[idx])) & 1;
        expanded = expanded << 1;
        expanded = expanded | bit_at_index;
    }
    expanded
}


fn shrink_48bit_block_to_32bit_block_with_s_tables(block_48bit : i64) -> i64 {
    let mut shrinked = 0i64;
    let block_6bit_count = 8;
    for idx in 0..block_6bit_count {
        let ones_at_block_index = bit_pattern_ones(6) << (42 - 6 * idx);
        let only_6bit_block = (ones_at_block_index) & block_48bit;
        let block_shited_left = only_6bit_block >> (42 - 6 * idx);
        let row_idx = (block_shited_left & 0b00001) | ((block_shited_left & 0b100000) >> 4);
        let col_idx = (block_shited_left & 0b011110) >> 1;
        let block_4bit = value_from_s_table_with_index((idx + 1) as u8, row_idx as u8, col_idx as u8) as i64;
        shrinked = (shrinked << 4) | block_4bit;
    }
    shrinked
}


const P : [u8; 32] = [
16, 7,20,21,
29,12,28,17,
1,15,23,26,
5,18,31,10,
2, 8,24,14,
32,27, 3, 9,
19,13,30, 6,
22,11, 4,25
];


fn permutate_block_32bit_with_p_table(block_32bit : i64) -> i64 {
    let mut permutated = 0i64;
    for idx in 0..32 {
        let bit_at_index = (block_32bit >> (32 - P[idx])) & 1;
        permutated = permutated << 1;
        permutated = permutated | bit_at_index;
    }
    permutated
}

fn value_from_s_table_with_index(s_idx: u8, row : u8, col: u8) -> u8 {
    match s_idx {
        1 if row < 4 && col < 16 => S1[(row * 16 + col) as usize],
        2 if row < 4 && col < 16 => S2[(row * 16 + col) as usize],
        3 if row < 4 && col < 16 => S3[(row * 16 + col) as usize],
        4 if row < 4 && col < 16 => S4[(row * 16 + col) as usize],
        5 if row < 4 && col < 16 => S5[(row * 16 + col) as usize],
        6 if row < 4 && col < 16 => S6[(row * 16 + col) as usize],
        7 if row < 4 && col < 16 => S7[(row * 16 + col) as usize],
        8 if row < 4 && col < 16 => S8[(row * 16 + col) as usize],
        _ => 0
    }
}


fn produce_right_block_32bit(left_block_32bit: i64,prev_right_block_32bit : i64, block_48bit: i64) -> i64 {
    left_block_32bit ^ encode_function(prev_right_block_32bit, block_48bit)
}


fn generate_last_pair_of_32bit_blocks(left_block : i64, right_block : i64, blocks_48bit: &Vec<i64>) -> (i64,i64) {
    let mut pair = (left_block, right_block);
    for idx in 0..blocks_48bit.len() {
        let next_left = pair.1;
        let next_right = produce_right_block_32bit(pair.0, pair.1, blocks_48bit[idx]);
        pair = (next_left, next_right);
    }
    pair
}


const IP_INVERSE : [u8; 64] = [
40,   8, 48,  16,  56, 24,  64, 32,
39,   7, 47,  15,  55, 23,  63, 31,
38,   6, 46,  14,  54, 22,  62, 30,
37,   5, 45,  13,  53, 21,  61, 29,
36,   4, 44,  12,  52, 20,  60, 28,
35,   3, 43,  11,  51, 19,  59, 27,
34,   2, 42,  10,  50, 18,  58, 26,
33,   1, 41,   9,  49, 17,  57, 25
];
fn last_permutation_with_ip_table(pair : (i64, i64)) -> i64 {
    let block = (pair.1 << 32) | pair.0;
    let mut permutation = 0i64;
    for idx in 0..64 {
        let bit_at_index_in_message = (block >> (64 - IP_INVERSE[idx])) & 1;
        permutation = permutation << 1;
        permutation = permutation | bit_at_index_in_message;
    }
    permutation
}


//S-Boxes :
const S1 : [u8; 64] = [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
			 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
			 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
			15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13];

const S2 : [u8; 64] = [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
			 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
			 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
			13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9];

const S3 : [u8; 64] = [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
			13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
			13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
			 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12];

const S4 : [u8; 64] = [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
			13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
			10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
			 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14];

const S5 : [u8; 64] = [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
			14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
			 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
			11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3];

const S6 : [u8; 64] = [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
			10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
			 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
			 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13];

const S7 : [u8; 64] = [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
			13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
			 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
			 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12];

const S8 : [u8; 64] = [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
			 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
			 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
			 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11];


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
    let subkeys = create_16_pairs_blocks_32bit(0xf0ccaaf, 0x556678f);
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

    assert_eq!(expected, convert_pairs_to_encrypted_48_bit_keys(&pairs_28_bit));
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


#[cfg(test)]
#[test]
//1111 0000 1010 1010 1111 0000 1010 1010 ->
//0111 1010 0001 0101 0101 0101 0111 1010 0001 0101 0101 0101
fn expand_f0aaf0aa_using_Etable_will_result_7a15557a1555() {
    let block_32bit = 0b11110000101010101111000010101010;
    let expected_block = 0b011110100001010101010101011110100001010101010101;
    assert_eq!(expected_block, expand_32bit_block_to_48bit_block_using_e_table(block_32bit));
}

#[cfg(test)]
#[test]
//0110 0001 0001 0111 1011 1010 1000 0110 0110 0101 0010 0111 ->
//0101 1100 1000 0010 1011 0101 1001 0111
fn shirnk_6117ba866537_using_Stable_will_result_5c82b597() {
    let block_48bit = 0x6117ba866527;
    let expected_output = 0x5c82b597;
    assert_eq!(expected_output, shrink_48bit_block_to_32bit_block_with_s_tables(block_48bit));
}


#[cfg(test)]
#[test]
fn value_in_5th_S_position_2_10_is_12() {
    let Stable_index = 5u8;
    let row = 2u8;
    let col = 10u8;
    let expected = 12u8;
    assert_eq!(expected, value_from_s_table_with_index(Stable_index, row, col));
}


#[cfg(test)]
#[test]
fn test_value_from_s_table_is_0_when_row_or_col_is_too_big() {
    let s_table_index = 4;
    let row = 4;
    let col = 15;
    let expected = 0;
    assert_eq!(expected, value_from_s_table_with_index(s_table_index, row, col));
}


#[cfg(test)]
#[test]
//1111 0000 1010 1010 1111 0000 1010 1010
//0001 1011 0000 0010 1110 1111 1111 1100 0111 0000 0111 0010

//0010 0011 0100 1010 1010 1001 1011 1011
fn encode_function_returns_234aa9bb() {
    let (block_32bit, block_48bit) = (0xf0aaf0aa, 0x1b02effc7072);
    let output = 0x234aa9bb;
    assert_eq!(output, encode_function(block_32bit, block_48bit));
}


#[cfg(test)]
#[test]
//0101 1100 1000 0010 1011 0101 1001 0111
//0010 0011 0100 1010 1010 1001 1011 1011
fn permutate_5c82b597_by_P_table_will_output_234559bb() {
    let input = 0x5c82b597;
    let output = 0x234aa9bb;
    assert_eq!(output, permutate_block_32bit_with_p_table(input));
}


#[cfg(test)]
#[test]
//l0 = 1100 1100 0000 0000 1100 1100 1111 1111
//r0 = 1111 0000 1010 1010 1111 0000 1010 1010
//K1 = 0001 1011 0000 0010 1110 1111 1111 1100 0111 0000 0111 0010
//R1 = 1110 1111 0100 1010 0110 0101 0100 0100
fn right_block_R1_created_from_l0_r0_K1() {
    let l0 = 0xcc00ccff;
    let r0 = 0xf0aaf0aa;
    let K1 = 0x1b02effc7072;
    let R1 = 0xef4a6544;
    assert_eq!(R1, produce_right_block_32bit(l0, r0, K1));
}


#[cfg(test)]
#[test]
//l0 = 1100 1100 0000 0000 1100 1100 1111 1111
//r0 = 1111 0000 1010 1010 1111 0000 1010 1010
//L16 = 0100 0011 0100 0010 0011 0010 0011 0100
//R16 = 0000 1010 0100 1100 1101 1001 1001 0101
fn final_pair_is_generated() {
    let l0 = 0xcc00ccff;
    let r0 = 0xf0aaf0aa;

    let L16 = 0x43423234;
    let R16 = 0xA4CD995;
    //because this 2 functions are tested they are safe to call here
    let subkeys = create_16_pairs_blocks_32bit(0xf0ccaaf, 0x556678f);
    let keys_block_48bit = convert_pairs_to_encrypted_48_bit_keys(&subkeys);
    assert_eq!((L16, R16), generate_last_pair_of_32bit_blocks(l0, r0, &keys_block_48bit));
}


#[cfg(test)]
#[test]
fn final_permutation_is_85E813540F0AB405_from_43423234_and_A4CD995() {
    let L16 = 0x43423234;
    let R16 = 0xA4CD995;
    let permutation = 0x85E813540F0AB405;
    assert_eq!(permutation, last_permutation_with_ip_table((L16, R16)));
}
