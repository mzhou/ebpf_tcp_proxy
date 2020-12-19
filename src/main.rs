use std::fmt;

use bpf_sys::{
    bpf_attach_type_BPF_SK_SKB_STREAM_PARSER, bpf_attach_type_BPF_SK_SKB_STREAM_VERDICT,
};
use redbpf::load::{Loader, LoaderError};

#[derive(Debug)]
enum MainError {
    AttachMap(redbpf::Error),
    Loader(LoaderError),
    Map,
}

impl fmt::Display for MainError {
    fn fmt(self: &Self, f: &mut fmt::Formatter) -> fmt::Result {
        use MainError::*;
        write!(
            f,
            "{}",
            match self {
                AttachMap(e) => format!("attach map {:?}", e),
                Loader(e) => format!("loader {:?}", e),
                Map => format!("map not found in ebpf program"),
            }
        )
    }
}

fn main() -> Result<(), MainError> {
    let sockmap_parser_elf =
        include_bytes!("../target/bpf/programs/sockmap_parser/sockmap_parser.elf");
    println!("elf is {} bytes", sockmap_parser_elf.len());

    let loader = Loader::load(sockmap_parser_elf).map_err(MainError::Loader)?;
    println!("loader created");
    let map = loader.map("sock_map").ok_or(MainError::Map)?;
    for sk_skb in loader.sk_skbs() {
        println!("found sk_skb {}", sk_skb.name());
        sk_skb
            .attach_map(
                &map,
                match sk_skb.name().as_str() {
                    "parser" => bpf_attach_type_BPF_SK_SKB_STREAM_PARSER,
                    "verdict" => bpf_attach_type_BPF_SK_SKB_STREAM_VERDICT,
                    _ => panic!("unknown program name"),
                },
                0,
            )
            .map_err(MainError::AttachMap)?;
    }

    Ok(())
}
