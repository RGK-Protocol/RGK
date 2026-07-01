//! Machine checks for the maintained RGK examples coverage matrix.

use std::collections::BTreeSet;

const MATRIX: &str = include_str!("../../../examples/contract-matrix.tsv");
const DEVNET_VERIFIER: &str = include_str!("../../../scripts/verify-devnet-evidence.sh");
const SILVERSCRIPT_MANIFEST: &str =
    include_str!("../../../examples/silverscript/artifacts/manifest.tsv");

#[test]
fn examples_contract_matrix_is_grounded_in_current_evidence() {
    let mut lines = MATRIX.lines();
    assert_eq!(
        lines.next(),
        Some("example_id\tcategory\tcapabilities\tlocal_evidence\tdevnet_markers\tcontract_source\tsilverscript_status\tcompile_artifact_status\tpublic_staging_status\texternal_equivalence_status")
    );

    let mut ids = BTreeSet::new();
    let mut rows = 0usize;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        assert_eq!(cols.len(), 10, "bad column count in {line}");
        let example_id = cols[0];
        assert!(!example_id.is_empty(), "empty example id");
        assert!(ids.insert(example_id), "duplicate example id {example_id}");
        for col in &cols {
            assert!(!col.is_empty(), "empty field in {example_id}");
            assert!(
                !col.contains("placeholder") && !col.contains("stub"),
                "non-production marker in {example_id}: {col}"
            );
        }
        assert_eq!(cols[5], "silverscript_and_rust_toccata_fixture");
        assert_eq!(cols[6], "silverscript_source_compiles");
        assert_eq!(cols[7], "checked_silverscript_json_artifact");
        assert_eq!(cols[8], "pending_public_staging");
        assert_eq!(cols[9], "not_required_for_rgk_native_core");
        assert!(
            SILVERSCRIPT_MANIFEST.contains(&format!(
                "{example_id}\texamples/silverscript/{example_id}.sil\texamples/silverscript/artifacts/{example_id}.json\t"
            )),
            "Silverscript manifest does not cover {example_id}"
        );

        for marker in cols[4].split(';') {
            assert!(
                DEVNET_VERIFIER.contains(&format!("require_regex \"{marker}\"")),
                "devnet marker {marker:?} is not enforced"
            );
        }
        rows += 1;
    }

    assert!(rows >= 4, "expected at least four evidenced examples");
}
