fn main() {
    cc::Build::new()
        .file("src/xdp_kern.c")
        .flag("-target")
        .flag("bpf")
        .flag("-O2")
        .flag("-g")
        .compile("xdp_prog");
}