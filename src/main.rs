use std::fmt;

use redbpf::load::{Loader, LoaderError};

#[derive(Debug)]
enum MainError {
    Loader(LoaderError),
}

impl fmt::Display for MainError {
    fn fmt(self: &Self, f: &mut fmt::Formatter) -> fmt::Result {
        use MainError::*;
        write!(
            f,
            "{}",
            match self {
                Loader(e) => format!("loader {:?}", e),
            }
        )
    }
}

fn main() -> Result<(), MainError> {
    let sockmap_parser_elf =
        include_bytes!("../target/bpf/programs/sockmap_parser/sockmap_parser.elf");
    println!("elf is {} bytes", sockmap_parser_elf.len());

    let mut loader = Loader::load(sockmap_parser_elf).map_err(MainError::Loader)?;
    println!("loader created");
    for _sk_skb in loader.sk_skbs_mut() {
        println!("found sk_skb");
    }
    if let Some(map) =  loader.map_mut("sock_map") {
        println!("found sock_map");
    }

    Ok(())
}
