use std::fmt;
use std::io::Read;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener};
use std::os::unix::io::{AsRawFd, RawFd};

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
    GetSockOpt(nix::Error),
    Loader(LoaderError),
    LocalAddr(std::io::Error),
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
                GetSockOpt(e) => format!("getsockopt {}", e),
                Loader(e) => format!("loader {:?}", e),
                LocalAddr(e) => format!("local_addr {}", e),
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
    let ss = TcpListener::bind("0.0.0.0:1234").map_err(MainError::Bind)?;
    loop {
        let (mut s, sa) = ss.accept().map_err(MainError::Accept)?;
        let a = mapped_socket_addr(&sa);
        println!("accepted from {}", a);
        let mss = nix::sys::socket::getsockopt(s.as_raw_fd(), TcpMaxSeg{}).map_err(MainError::GetSockOpt)?;
        println!("mss {}", mss);
        let la = mapped_socket_addr(&s.local_addr().map_err(MainError::LocalAddr)?);
        println!("remote {} local {}", a, la);
        let key = make_endpoints(a.ip(), la.ip(), a.port(), la.port());
        println!("key {:?}", key);
        let val = s.as_raw_fd();
        sock_hash.set(key, val);
        println!("socket added to map");
        // wait for close
        let mut dummy_buf = [0u8; 1];
        let read_result = s.read(&mut dummy_buf);
        println!("read has returned {:?}", read_result);
        sock_hash.delete(key);
    }
}

fn make_endpoints(
    remote_ip6: &Ipv6Addr,
    local_ip6: &Ipv6Addr,
    remote_port: u16,
    local_port: u16,
) -> Endpoints {
    Endpoints {
        remote_ip6: unsafe { core::mem::transmute(remote_ip6.octets()) }, // TODO: safe conversion
        local_ip6: unsafe { core::mem::transmute(local_ip6.octets()) },   // TODO: safe conversion
        remote_port: u32::swap_bytes(remote_port.into()),
        local_port: local_port.into(), // host byte order
    }
}

fn mapped_socket_addr(sa: &SocketAddr) -> SocketAddrV6 {
    match sa {
        SocketAddr::V4(sa_v4) => SocketAddrV6::new(sa_v4.ip().to_ipv6_mapped(), sa_v4.port(), 0, 0),
        SocketAddr::V6(sa_v6) => *sa_v6,
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TcpMaxSeg {
}

impl nix::sys::socket::GetSockOpt for TcpMaxSeg {
    type Val = i32;

    fn get(&self, fd: RawFd) -> nix::Result<Self::Val> {
        unsafe {
            let mut val: i32 = 0;
            let mut len: libc::socklen_t = core::mem::size_of::<i32>() as libc::socklen_t;
            let res = libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_MAXSEG, &mut val as *mut _ as *mut libc::c_void, &mut len as *mut libc::socklen_t);
            nix::errno::Errno::result(res)?;
            Ok(val)
        }
    }
}
