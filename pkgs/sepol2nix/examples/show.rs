use std::str::FromStr;
fn main() {
    let source =
        std::fs::read_to_string("pkgs/sepol2nix/tests/fixtures/module.fc").expect("readable");
    let file = sepol2nix::file_context::FileContextFile::from_str(&source).expect("parses");
    println!("{file}");
}
