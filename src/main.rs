use std::fmt;
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::io::AsRawFd;

use bpf_sys::{
    bpf_attach_type_BPF_SK_SKB_STREAM_PARSER, bpf_attach_type_BPF_SK_SKB_STREAM_VERDICT,
};
use redbpf::load::{Loader, LoaderError};
use redbpf::HashMap;

use ebpf_tcp_proxy::sockmap_parser::Endpoints;

#[derive(Debug)]
enum MainError {
    Accept(std::io::Error),
    AttachMap(redbpf::Error),
    Bind(std::io::Error),
    Loader(LoaderError),
    MapCast,
    Map,
}

impl fmt::Display for MainError {
    fn fmt(self: &Self, f: &mut fmt::Formatter) -> fmt::Result {
        use MainError::*;
        write!(
            f,
            "{}",
            match self {
                Accept(e) => format!("accept {}", e),
                AttachMap(e) => format!("attach map {:?}", e),
                Bind(e) => format!("bind {}", e),
                Loader(e) => format!("loader {:?}", e),
                Map => format!("map not found in ebpf program"),
                MapCast => format!("map key/value type mismatch"),
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
    let map = loader.map("sock_hash").ok_or(MainError::Map)?;
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
    println!("bpf init done");

    // should be SockMap, but api is the same as HashMap, so use it for now
    let sock_hash = HashMap::<Endpoints, i32>::new(map).map_err(|_| MainError::MapCast)?;
    let ss = TcpListener::bind("[::]:1234").map_err(MainError::Bind)?;
    loop {
        let (mut s, a) = ss.accept().map_err(MainError::Accept)?;
        println!("accepted from {}", a);
        match a {
            SocketAddr::V6(a) => {
                let key = Endpoints{
                    remote_ip6: unsafe { core::mem::transmute(a.ip().octets()) },
                    //remote_ip6: [0u32; 4],
                    local_ip6: [0u32; 4],
                    remote_port: u32::swap_bytes(a.port().into()),
                    local_port: 0,
                };
                let val = s.as_raw_fd();
                sock_hash.set(key, val);
                println!("socket added to map");
                // wait for close
                let mut dummy_buf = [0u8; 1];
                let read_result = s.read(&mut dummy_buf);
                println!("read has returned {:?}", read_result);
                sock_hash.delete(key);
            },
            SocketAddr::V4(_) => {
            },
        }
    }
}
