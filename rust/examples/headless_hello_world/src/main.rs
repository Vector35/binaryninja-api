use binaryninja::binaryview::{BinaryView, BinaryViewExt};
use binaryninja::filemetadata::FileMetadata;

fn main() {
  println!("Hello world!");

  let file_metadata = FileMetadata::new();
  let bv = BinaryView::from_filename(&file_metadata, "/bin/cat").expect(":/");

  // println!("{}", bv.name);

  println!("Updating analysis...");
  bv.update_analysis_and_wait();
  bv.update_analysis_and_wait();
  println!("Done");

  if bv.has_functions() {
    println!("This binary contains functions:");
    for func in bv.functions().iter() {
      println!("  there's a function at: 0x{:#08x}", func.start());
    }
  } else {
    println!("This binary has no functions");
  }

  file_metadata.close();
}
