fn main() {
    let path = std::env::args().nth(1).expect("path argument");
    let source = std::fs::read_to_string(path).expect("readable source");
    for tree in sepol2nix::lexer::lex(&source).expect("lexes") {
        println!("{tree:#?}");
    }
}
