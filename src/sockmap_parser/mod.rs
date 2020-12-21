#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Endpoints {
    pub remote_ip6: [u32; 4], // network byte order
    pub local_ip6: [u32; 4],  // network byte order
    pub remote_port: u32,     // network byte order
    pub local_port: u32,      // host byte order
}
