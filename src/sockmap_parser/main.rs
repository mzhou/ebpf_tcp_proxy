#![no_main]
#![no_std]

use redbpf_probes::bindings::__sk_buff;
use redbpf_probes::socket_filter::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[no_mangle]
#[link_section = "socketfilter/parser"]
fn parser(skb: *const __sk_buff) -> i32 {
    unsafe {
        (*skb).len as i32
    }
}
