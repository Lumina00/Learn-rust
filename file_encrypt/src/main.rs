use std::env;

mod crypto;
use crypto::*;

fn main(){
    let args: Vec<String> = env::args().collect();
    if args[1] == "-r".to_string(){
        verify(&args[2]);
        }
    else if args[1] == "-n".to_string(){
    store();
    }
}
