#![forbid(unsafe_code)]

#[cfg(not(feature = "live-kaspa-wrpc"))]
fn main() {
    eprintln!("rgk-testnet-staging-address requires --features live-kaspa-wrpc");
    std::process::exit(2);
}

#[cfg(feature = "live-kaspa-wrpc")]
fn main() {
    use kaspa_addresses::Prefix;

    let mut args = std::env::args().skip(1);
    let first = args.next();
    let preflight = first.as_deref() == Some("--preflight");
    let network = if preflight {
        args.next()
            .or_else(|| std::env::var("RGK_LIVE_KASPA_NETWORK").ok())
            .unwrap_or_else(|| "testnet-12".to_string())
    } else {
        first
            .or_else(|| std::env::var("RGK_LIVE_KASPA_NETWORK").ok())
            .unwrap_or_else(|| "testnet-12".to_string())
    };

    if preflight {
        match rgk_e2e::TestnetStagingPreflight::new(&network) {
            Ok(preflight) => {
                print!("{}", preflight.render());
                return;
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(2);
            }
        }
    }

    let preflight = match rgk_e2e::TestnetStagingPreflight::new(&network) {
        Ok(preflight) => preflight,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    let (_keypair, address) = rgk_e2e::deterministic_live_staging_keypair(Prefix::Testnet);
    println!("RGK public testnet staging funding");
    println!("network={}", preflight.network);
    println!("address={address}");
    println!("scope=testnet-only deterministic staging key");
    println!(
        "required_min_value_real_zk={}",
        preflight.required_min_value_real_zk
    );
    println!(
        "required_min_value_verifier_only={}",
        preflight.required_min_value_verifier_only
    );
    println!(
        "preflight_id=0x{}",
        rgk_core::to_hex(&preflight.preflight_id)
    );
}
