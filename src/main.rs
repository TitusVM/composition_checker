use wasmparser::{self, Payload};

fn main() {
    let composed = get_file_as_byte_vec("signed_composed.wasm");
    let components = split_composition(&composed);
    let pub_key = wasmsign2::PublicKey::from_any_file("keys/public.key").unwrap();

    println!("Extracted {} components", components.len());

    for component in &components {
        let clean_extract;
        if component.to_vec() != composed {
            clean_extract = clean_extracted(component);
        } else {
            clean_extract = component.to_vec();
        }
        let _ = match pub_key.verify(&mut &clean_extract[..], None) {
            Ok(()) => {
                println!("Signature is OK");
            }
            Err(err) => {
                println!("Err: {:?}", err);
            }
        };
    };
}


/**
 * Dirty hack to remove last couple of bytes from an extracted component, this is to be able to verify it's signature.
 */
fn clean_extracted(extracted: &Vec<u8>) -> Vec<u8> {
    let mut end_last_section = 0;
    for payload in wasmparser::Parser::new(0).parse_all(&extracted) {
        match payload {
            Ok(Payload::CustomSection(reader)) => {
                end_last_section = reader.range().end;
            }
            _ => {}
        }
    };
    extracted[0..end_last_section].to_vec()
}

fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open(&filename).expect("no file found");
    let metadata = std::fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

/*
fn is_subvec(mainvec: &Vec<u8>, subvec: &Vec<u8>) -> bool {
    if subvec.len() == 0 { return true; }
    if mainvec.len() == 0 { return false; }
    if subvec.len() > mainvec.len() { return false; }

    'outer: for i in 0..mainvec.len() {
        for j in 0..subvec.len() {
            if mainvec[i+j] != subvec[j] {
                continue 'outer;
            }
        }
        return true;
    }
    return false;
}*/

/**
 * This function can extract component binaries from a composed (wac plug) component.
 * 
 */

fn split_composition(composition: &Vec<u8>) -> Vec<Vec<u8>> {
    const SECTION_DELIMITER: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];
    const SIGNATURE_DELIMITER: [u8; 20] = [
        0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00,
        0x00, 0x75, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61,
        0x74, 0x75, 0x72, 0x65,
    ];
    let mut components: Vec<Vec<u8>> = Vec::new();
    let mut bookmark = 0; // Start from the beginning
    let mut counter = 0;

    for i in 0..(composition.len() - SIGNATURE_DELIMITER.len()) {
        if composition[i..(i + SECTION_DELIMITER.len())] == SECTION_DELIMITER {
            if composition[i..(i + SIGNATURE_DELIMITER.len())] == SIGNATURE_DELIMITER {
                //println!("Found a signed component at position {}, counter = {}", i, counter);
                if counter == 0 {
                    // The first signature is the one from the composed component so we store the whole component
                    components.push(composition.to_vec());
                } else if bookmark != 0{
                    components.push(composition[bookmark..i].to_vec());
                }
                // Update bookmark to the start of the new signed component
                bookmark = i;
                counter += 1;
            }
        }
    }

    // Push the last component if it exists
    if bookmark < composition.len() {
        components.push(composition[bookmark..].to_vec());
    }

    components
}