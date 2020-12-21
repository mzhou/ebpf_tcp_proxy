#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Endpoints {
    pub remote_ip6: [u32; 4],
    pub local_ip6: [u32; 4],
    pub remote_port: u32,
    pub local_port: u32,
}
