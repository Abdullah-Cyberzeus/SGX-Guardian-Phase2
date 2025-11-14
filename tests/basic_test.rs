use sgx_guardian_client::add_numbers;

#[test]
fn test_add_numbers() {
    assert_eq!(add_numbers(2, 3), 5);
}
