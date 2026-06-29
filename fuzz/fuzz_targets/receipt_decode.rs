#![no_main]

use libfuzzer_sys::fuzz_target;
use rgk_core::{receipt_commitment, Canonical, RgkReceipt};
use rgk_receipt::ReceiptVerifier;

fuzz_target!(|data: &[u8]| {
    if let Ok(receipt) = RgkReceipt::decode_canonical(data) {
        assert_eq!(receipt.encode_canonical(), data);
        receipt
            .validate_structure()
            .expect("decoded receipt is valid");

        let id = receipt_commitment(&receipt);
        let verified = ReceiptVerifier::verify_local_structured(
            &receipt,
            receipt.covenant_id,
            &receipt.old_state,
            receipt.chain_id,
        )
        .expect("self-consistent decoded receipt verifies");
        assert_eq!(verified, id);
    }
});
