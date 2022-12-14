#![no_main]
#![no_std]

use cty::*;
use redbpf_macros::map;
use redbpf_probes::bindings::__sk_buff;
use redbpf_probes::socket_filter::prelude::*;

use ebpf_tcp_proxy::sockmap_parser::Endpoints;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut sock_hash: SockHash<Endpoints, u32> = SockHash::with_max_entries(32767);

#[no_mangle]
#[link_section = "sk_skb/parser"]
fn parser(skb: *mut __sk_buff) -> i32 {
    unsafe { (*skb).len as i32 }
}

#[no_mangle]
#[link_section = "sk_skb/verdict"]
fn verdict(skb: *mut __sk_buff) -> i32 {
    unsafe {
        let mut key = Endpoints {
            remote_ip6: (*skb).remote_ip6,
            local_ip6: (*skb).local_ip6,
            remote_port: (*skb).remote_port,
            local_port: (*skb).local_port,
        };
        bpf_trace_printk(&core::mem::transmute::<_, [u8; 40]>(key));
        bpf_sk_redirect_hash(
            skb,
            sock_hash.get_def_mut() as *mut c_void,
            &mut key as *mut _ as *mut c_void,
            0,
        )
    }
}
