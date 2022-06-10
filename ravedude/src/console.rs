use anyhow::Context as _;
use std::io::Read as _;
use std::io::Write as _;

use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use anyhow::anyhow;

use defmt_decoder::{DecodeError, Frame, Locations, Table};

pub fn open(port: &std::path::Path, baudrate: u32,  elf: Option<PathBuf>) -> anyhow::Result<()> {
    let mut rx = serialport::new(port.to_string_lossy(), baudrate)
        .timeout(std::time::Duration::from_secs(2))
        .open_native()
        .with_context(|| format!("failed to open serial port `{}`", port.display()))?;
    let mut tx = rx.try_clone_native()?;

    // Set a CTRL+C handler to terminate cleanly instead of with an error.
    ctrlc::set_handler(move || {
        eprintln!("");
        eprintln!("Exiting.");
        std::process::exit(0);
    }).context("failed setting a CTRL+C handler")?;


    let verbose = false;
    let show_skipped_frames = true;
    let json = false;

    defmt_decoder::log::init_logger(verbose, json, move |metadata| match verbose {
        false => defmt_decoder::log::is_defmt_frame(metadata), // We display *all* defmt frames, but nothing else.
        true => true,                                          // We display *all* frames.
    });
    
    let bytes = fs::read(&elf.unwrap())?;
    
    let table = Table::parse(&bytes)?.ok_or_else(|| anyhow!(".defmt data not found"))?;
    let locs = table.get_locations(&bytes)?;
    
    let locs = if table.indices().all(|idx| locs.contains_key(&(idx as u64))) {
        Some(locs)
    } else {
        log::warn!("(BUG) location info is incomplete; it will be omitted from the output");
        None
    };
    
    let mut stream_decoder = table.new_stream_decoder();
    
    let current_dir = env::current_dir()?;
    let stdin = io::stdin();
    let mut stdin = stdin.lock();

    // Spawn a thread for the receiving end because stdio is not portably non-blocking...
    /*std::thread::spawn(move || loop {
        let mut buf = [0u8; 4098];
        match rx.read(&mut buf) {
            Ok(count) => {
                stdout.write(&buf[..count]).unwrap();
                stdout.flush().unwrap();
            }
            Err(e) => {
                assert!(e.kind() == std::io::ErrorKind::TimedOut);
            }
        }
    });*/

    let mut buf = [0u8; 4098];
    loop {
        match rx.read(&mut buf) {
            Ok(count) => {
                //println!("Recv {} bytes", count);
                stream_decoder.received(&buf[..count]);
                
                // decode the received data
                loop {
                    match stream_decoder.decode() {
                        Ok(frame) => forward_to_logger(&frame, location_info(&locs, &frame, &current_dir)),
                        Err(DecodeError::UnexpectedEof) => {
                            //println!("eof");
                            break
                        }
                        Err(DecodeError::Malformed) => match table.encoding().can_recover() {
                            // if recovery is impossible, abort
                            false => return Err(DecodeError::Malformed.into()),
                            // if recovery is possible, skip the current frame and continue with new data
                            true => {
                                if show_skipped_frames || verbose {
                                    println!("(HOST) malformed frame skipped");
                                    println!("└─ {} @ {}:{}", env!("CARGO_PKG_NAME"), file!(), line!());
                                }
                                continue;
                            }
                        },
                    }
                }
            }
            Err(e) => {
                assert!(e.kind() == std::io::ErrorKind::TimedOut);
            }
        }

        // read from stdin and push it to the decoder
        //let count = stdin.read(&mut buf)?;
        
        //tx.write(&buf[..count])?;
        //tx.flush()?;
    }
}

type LocationInfo = (Option<String>, Option<u32>, Option<String>);

fn forward_to_logger(frame: &Frame, location_info: LocationInfo) {
    let (file, line, mod_path) = location_info;
    defmt_decoder::log::log_defmt(frame, file.as_deref(), line, mod_path.as_deref());
}

fn location_info(locs: &Option<Locations>, frame: &Frame, current_dir: &Path) -> LocationInfo {
    let (mut file, mut line, mut mod_path) = (None, None, None);

    // NOTE(`[]` indexing) all indices in `table` have been verified to exist in the `locs` map
    let loc = locs.as_ref().map(|locs| &locs[&frame.index()]);

    if let Some(loc) = loc {
        // try to get the relative path, else the full one
        let path = loc.file.strip_prefix(&current_dir).unwrap_or(&loc.file);

        file = Some(path.display().to_string());
        line = Some(loc.line as u32);
        mod_path = Some(loc.module.clone());
    }

    (file, line, mod_path)
}