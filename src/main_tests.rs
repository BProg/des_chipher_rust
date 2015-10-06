use super::*;


#[test]
fn rotatig_bit_with_1_on_firstbit() {
    let bit_to_rotate : i64 = 0b1111000011110000111100001111;
    assert_eq!(0b1110000111100001111000011111, bit_rotate_left(bit_to_rotate, 1));
}


#[test]
fn rotatig_bit_with_2_positions() {
    let bit_to_rotate : i64 = 0b1111_0000_1111_0000_1111_0000_1111;
    assert_eq!(0b1100_0011_1100_0011_1100_0011_1111, bit_rotate_left(bit_to_rotate, 2));
}


#[test]
fn ones_for_2_is_11() {
    assert_eq!(0b11, bit_pattern_containing_ones(2));
}


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


#[test]
fn test_spliting_a_56_bit_key_into_2_x_28_keys() {
    let original_key = 0b11110000110011001010101011110101010101100110011110001111;
    let expected_left = 0b1111000011001100101010101111;
    let expected_right = 0b0101010101100110011110001111;
    assert_eq!((expected_left, expected_right), split_key(original_key, 56));
}


#[test]
fn generate_key_plus_based_on_pc1_table() {
    let key = 0b0001001100110100010101110111100110011011101111001101111111110001;
    let key_plus = 0b11110000110011001010101011110101010101100110011110001111;
    assert_eq!(key_plus, generate_key_plus(key));
}

#[test]
fn creating_key_based_on_pairs_and_PC2_table() {
    let left = 0b1110000110011001010101011111;
    let right = 0b1010101011001100111100011110;
    let expected_key = 0b000110110000001011101111111111000111000001110010;
    assert_eq!(expected_key, key_kn_from_pair(left, right));
}


#[test]
fn creating_48_bit_key_based_on_maximum_pairs() {
    let left = 0b1111_1111_1111_1111_1111_1111_1111;
    let right = 0b1111_1111_1111_1111_1111_1111_1111;
    let expected = 0b1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111;
    assert_eq!(expected, key_kn_from_pair(left, right));
}
