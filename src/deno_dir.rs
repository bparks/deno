use fs;
use sha1;
use std;
use std::path::Path;
use std::path::PathBuf;

// Example: /Users/rld/.deno/
static mut ROOT: Option<PathBuf> = None;
static mut DEPS: Option<PathBuf> = None;
static mut GEN: Option<PathBuf> = None;
pub enum Dirname {
  Root,
  // In the Go code this was called SrcDir. Renaming to Deps.
  // Example: /Users/rld/.deno/deps/
  Deps,
  // In the Go code this was called CacheDir. Renaming to GEN.
  // Example: /Users/rld/.deno/gen/
  Gen,
}
pub use self::Dirname::*;

pub fn path(dirname: Dirname) -> &'static Path {
  setup().expect("deno_dir setup failed.");
  let pb_option = unsafe {
    match dirname {
      Root => &ROOT,
      Deps => &DEPS,
      Gen => &GEN,
    }
  };
  match pb_option {
    Some(ref x) => x.as_path(),
    None => panic!(),
  }
}

// https://github.com/ry/deno/blob/golang/deno_dir.go#L99-L111
pub fn setup() -> std::io::Result<()> {
  // Only setup once.
  if unsafe { ROOT != None } {
    return Ok(());
  }
  let home_dir = std::env::home_dir().expect("Could not get home directory.");
  // TODO(ry) Handle alternate deno dirs specified as command-line flag.
  // unsafe because of mutable statics.

  unsafe {
    ROOT = Some(home_dir.join(".deno"));
    DEPS = Some(path(Root).join("deps"));
    GEN = Some(path(Root).join("gen"));
  }
  fs::mkdir(path(Gen))?;
  fs::mkdir(path(Deps))?;

  debug!("root {}", path(Root).display());
  debug!("gen {}", path(Gen).display());
  debug!("deps {}", path(Deps).display());

  Ok(())
}

// https://github.com/ry/deno/blob/golang/deno_dir.go#L32-L35
pub fn cache_path(filename: &str, source_code: &str) -> PathBuf {
  let cache_key = source_code_hash(filename, source_code);
  let r = &path(Gen);
  r.join(cache_key + ".js")
}

#[test]
fn test_cache_path() {
  assert_eq!(
    path(Gen).join("a3e29aece8d35a19bf9da2bb1c086af71fb36ed5.js"),
    cache_path("hello.ts", "1+2")
  );
}

// https://github.com/ry/deno/blob/golang/deno_dir.go#L25-L30
fn source_code_hash(filename: &str, source_code: &str) -> String {
  let mut m = sha1::Sha1::new();
  m.update(filename.as_bytes());
  m.update(source_code.as_bytes());
  return m.digest().to_string();
}

#[test]
fn test_source_code_hash() {
  assert_eq!(
    "a3e29aece8d35a19bf9da2bb1c086af71fb36ed5",
    source_code_hash("hello.ts", "1+2")
  );
  // Different source_code should result in different hash.
  assert_eq!(
    "914352911fc9c85170908ede3df1128d690dda41",
    source_code_hash("hello.ts", "1")
  );
  // Different filename should result in different hash.
  assert_eq!(
    "2e396bc66101ecc642db27507048376d972b1b70",
    source_code_hash("hi.ts", "1+2")
  );
}

#[cfg(test)]
pub fn reset() -> std::io::Result<()> {
  std::fs::remove_dir_all(path(Root))?;
  unsafe {
    ROOT = None;
    DEPS = None;
    GEN = None;
  }
  setup()
}

pub fn load_cache(
  filename: &str,
  source_code: &str,
) -> std::io::Result<String> {
  let path = cache_path(filename, source_code);
  debug!("load_cache {}", path.display());
  fs::read_file_sync(&path)
}
