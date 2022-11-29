use std::fs;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    vergen::vergen(vergen::Config::default())?;

    let protos = &[
        "./proto/chasm/state.proto",

        "./proto/chasm/query.proto",
        "./proto/chasm/tx.proto",

        "./proto/cosmos-sdk-go/proto/cosmos/auth/v1beta1/auth.proto",
        "./proto/cosmos-sdk-go/proto/cosmos/auth/v1beta1/query.proto",
        "./proto/wasmd-go/proto/cosmwasm/wasm/v1/query.proto",
        "./proto/wasmd-go/proto/cosmwasm/wasm/v1/types.proto",
        "./proto/wasmd-go/proto/cosmwasm/wasm/v1/tx.proto",

        "./proto/cosmos-tx/cosmos-tx-service.proto",
    ];
    let includes = &[
        "./proto/cosmos-tx", // for cosmos-tx-service.proto
        "./proto/chasm",
        "./proto/cosmos-sdk-go/proto",
        "./proto/wasmd-go/proto/",
        "./proto/cosmos-sdk-go/third_party/proto",
    ];

    #[cfg(feature="standalone")]
    let build_standalone = true;
    #[cfg(not(feature="standalone"))]
    let build_standalone = false;

    #[cfg(feature="build-proto")]
    let build_proto = true;
    #[cfg(not(feature="build-proto"))]
    let build_proto = false;

    if build_standalone && build_proto {
        let out_dir_client = format!("{}/src/proto/client", std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let out_dir_no_client = format!("{}/src/proto/no-client", std::env::var("CARGO_MANIFEST_DIR").unwrap());
        fs::create_dir_all(out_dir_client.clone())?;
        fs::create_dir_all(out_dir_no_client.clone())?;

        // build proto for both the standalone and library case.
        tonic_build::configure()
            .build_client(true)
            .build_server(false)
            .out_dir(out_dir_client)
            .compile(protos, includes)?;

        tonic_build::configure()
            .build_client(false)
            .build_server(false)
            .out_dir(out_dir_no_client)
            .compile(protos, includes)?;
    }
    
    Ok(())
}

