use redbpf::load::Loader;

fn main() {
    let mut loader = Loader::load_file("iotop.elf").expect("error loading probe");

    // attach all the kprobes defined in iotop.elf
    for kprobe in loader.kprobes_mut() {
        kprobe
            .attach_kprobe(&kprobe.name(), 0)
            .expect(&format!("error attaching program {}", kprobe.name()));
    }
}
