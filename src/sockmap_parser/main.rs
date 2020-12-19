#![no_main]
#![no_std]

use cty::*;
use redbpf_macros::map;
use redbpf_probes::bindings::__sk_buff;
use redbpf_probes::socket_filter::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut sock_map: SockMap<i32, i32> = SockMap::with_max_entries(2);

#[no_mangle]
#[link_section = "socketfilter/parser"]
fn parser(skb: *mut __sk_buff) -> i32 {
    unsafe { (*skb).len as i32 }
}

#[no_mangle]
#[link_section = "socketfilter/verdict"]
fn verdict(skb: *mut __sk_buff) -> i32 {
    let idx = 0u32;
    unsafe { bpf_sk_redirect_map(skb, sock_map.get_def_mut() as *mut c_void, idx, 0) }
}
