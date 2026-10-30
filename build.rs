fn main() {
    println!("cargo:rerun-if-changed=proto/sync.proto");
    if std::env::var("CARGO_FEATURE_GRPC").is_ok() {
        // SAFETY: build scripts are single-threaded at this point.
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
        tonic_build::compile_protos("proto/sync.proto").unwrap();
    }
}
