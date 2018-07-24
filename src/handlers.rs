// Copyright 2018 the Deno authors. All rights reserved. MIT license.
use binding::{deno_buf, deno_set_response, DenoC};
use deno_dir;
use flatbuffers;
use fs;
use libc::c_char;
use msg_generated::deno as msg;
use std;
use std::ffi::CStr;
use std::fs::File;
use std::path::Path;
use std::result::Result;
use url;
use url::Url;

const ASSET_PREFIX: &str = "/$asset$/";

#[test]
fn test_url() {
  let issue_list_url = Url::parse("https://github.com/rust-lang").unwrap();
  assert!(issue_list_url.scheme() == "https");
}

// Help. Is there a way to do this without macros?
// Want: fn str_from_ptr(*const c_char) -> &str
macro_rules! str_from_ptr {
  ($ptr:expr) => {{
    let cstr = unsafe { CStr::from_ptr($ptr as *const i8) };
    cstr.to_str().unwrap()
  }};
}

/*
// reply_start partially implemented here https://gist.github.com/ry/297c83e0ac8722c045db1b097cdb6afc
pub fn deno_handle_msg_from_js(d: *const DenoC, buf: deno_buf) {
    let s = std::slice::from_raw_parts(buf.data_ptr, buf.data_len);
    buf.data_ptr
    get_root()
}
*/

// Prototype: https://github.com/ry/deno/blob/golang/os.go#L56-L68
#[allow(dead_code)]
fn src_file_to_url<P: AsRef<Path>>(filename: P) -> String {
  let filename = filename.as_ref().to_path_buf();
  let src = deno_dir::path(deno_dir::Deps).to_path_buf();

  if filename.starts_with(&src) {
    let rest = filename.strip_prefix(&src).unwrap();
    "http://".to_string() + rest.to_str().unwrap()
  } else {
    String::from(filename.to_str().unwrap())
  }
}

#[test]
fn test_src_file_to_url() {
  assert_eq!("hello", src_file_to_url("hello"));
  assert_eq!("/hello", src_file_to_url("/hello"));
  let x = String::from(
    deno_dir::path(deno_dir::Deps)
      .join("hello/world.txt")
      .to_str()
      .unwrap(),
  );
  assert_eq!("http://hello/world.txt", src_file_to_url(x));
}

// Prototype: https://github.com/ry/deno/blob/golang/os.go#L70-L98
// Returns (module name, local filename)
fn resolve_module(
  module_specifier: &str,
  containing_file: &str,
) -> Result<(String, String), url::ParseError> {
  info!(
    "resolve_module before module_specifier {} containing_file {}",
    module_specifier, containing_file
  );

  //let module_specifier = src_file_to_url(module_specifier);
  //let containing_file = src_file_to_url(containing_file);
  //let base_url = Url::parse(&containing_file)?;

  let j: Url =
    if containing_file == "." || Path::new(module_specifier).is_absolute() {
      Url::from_file_path(module_specifier).unwrap()
    } else if containing_file.ends_with("/") {
      let base = Url::from_directory_path(&containing_file).unwrap();
      base.join(module_specifier)?
    } else {
      let base = Url::from_file_path(&containing_file).unwrap();
      base.join(module_specifier)?
    };

  let mut p = j.to_file_path()
    .unwrap()
    .into_os_string()
    .into_string()
    .unwrap();

  if cfg!(target_os = "windows") {
    // On windows, replace backward slashes to forward slashes.
    // TODO(piscisaureus): This may not me be right, I just did it to make
    // the tests pass.
    p = p.replace("\\", "/");
  }

  let module_name = p.to_string();
  let filename = p.to_string();

  Ok((module_name, filename))
}

// https://github.com/ry/deno/blob/golang/os_test.go#L16-L87
#[test]
fn test_resolve_module() {
  // The `add_root` macro prepends "C:" to a string if on windows; on posix
  // systems it returns the input string untouched. This is necessary because
  // `Url::from_file_path()` fails if the input path isn't an absolute path.
  macro_rules! add_root {
    ($path:expr) => {
      if cfg!(target_os = "windows") {
        concat!("C:", $path)
      } else {
        $path
      }
    };
  }

  let test_cases = [
    (
      "./subdir/print_hello.ts",
      add_root!(
        "/Users/rld/go/src/github.com/ry/deno/testdata/006_url_imports.ts"
      ),
      add_root!(
        "/Users/rld/go/src/github.com/ry/deno/testdata/subdir/print_hello.ts"
      ),
      add_root!(
        "/Users/rld/go/src/github.com/ry/deno/testdata/subdir/print_hello.ts"
      ),
    ),
    (
      "testdata/001_hello.js",
      add_root!("/Users/rld/go/src/github.com/ry/deno/"),
      add_root!("/Users/rld/go/src/github.com/ry/deno/testdata/001_hello.js"),
      add_root!("/Users/rld/go/src/github.com/ry/deno/testdata/001_hello.js"),
    ),
    (
      add_root!("/Users/rld/src/deno/hello.js"),
      ".",
      add_root!("/Users/rld/src/deno/hello.js"),
      add_root!("/Users/rld/src/deno/hello.js"),
    ),
    (
      add_root!("/this/module/got/imported.js"),
      add_root!("/that/module/did/it.js"),
      add_root!("/this/module/got/imported.js"),
      add_root!("/this/module/got/imported.js"),
    ),
    /*
        (
            "http://localhost:4545/testdata/subdir/print_hello.ts",
            add_root!("/Users/rld/go/src/github.com/ry/deno/testdata/006_url_imports.ts"),
            "http://localhost:4545/testdata/subdir/print_hello.ts",
            path.Join(SrcDir, "localhost:4545/testdata/subdir/print_hello.ts"),
        ),
        (
            path.Join(SrcDir, "unpkg.com/liltest@0.0.5/index.ts"),
            ".",
            "http://unpkg.com/liltest@0.0.5/index.ts",
            path.Join(SrcDir, "unpkg.com/liltest@0.0.5/index.ts"),
        ),
        (
            "./util",
            path.Join(SrcDir, "unpkg.com/liltest@0.0.5/index.ts"),
            "http://unpkg.com/liltest@0.0.5/util",
            path.Join(SrcDir, "unpkg.com/liltest@0.0.5/util"),
        ),
        */
  ];
  for &test in test_cases.iter() {
    let module_specifier = String::from(test.0);
    let containing_file = String::from(test.1);
    let (module_name, filename) =
      resolve_module(&module_specifier, &containing_file).unwrap();
    assert_eq!(module_name, test.2);
    assert_eq!(filename, test.3);
  }
}

fn reply_error(d: *const DenoC, cmd_id: u32, msg: &String) {
  let mut builder = flatbuffers::FlatBufferBuilder::new();
  // println!("reply_error{}", msg);
  let args = msg::BaseArgs {
    cmdId: cmd_id,
    error: builder.create_string(msg),
    ..Default::default()
  };
  set_response_base(d, &mut builder, &args)
}

fn set_response_base(
  d: *const DenoC,
  builder: &mut flatbuffers::FlatBufferBuilder,
  args: &msg::BaseArgs,
) {
  let base = msg::CreateBase(builder, &args);
  builder.finish(base);
  let data = builder.get_active_buf_slice();
  // println!("buf slice {} {} {} {} {}", data[0], data[1], data[2], data[3], data[4]);
  let buf = deno_buf {
    // TODO(ry)
    // The deno_buf / ImportBuf / ExportBuf semantics should be such that we do not need to yield
    // ownership. Temporarally there is a hack in ImportBuf that when alloc_ptr is null, it will
    // memcpy the deno_buf into V8 instead of doing zero copy.
    alloc_ptr: 0 as *mut u8,
    alloc_len: 0,
    data_ptr: data.as_ptr() as *mut u8,
    data_len: data.len(),
  };
  // println!("data_ptr {:p}", data_ptr);
  // println!("data_len {}", data.len());
  unsafe { deno_set_response(d, buf) }
}

fn get_source_code(
  module_name: &str,
  filename: &str,
) -> std::io::Result<String> {
  if is_remote(module_name) {
    unimplemented!();
  } else if module_name.starts_with(ASSET_PREFIX) {
    assert!(false, "Asset resolution should be done in JS, not Rust.");
    unimplemented!();
  } else {
    assert!(
      module_name == filename,
      "if a module isn't remote, it should have the same filename"
    );
    fs::read_file_sync(Path::new(filename))
  }
}

struct CodeFetchOutput {
  module_name: String,
  filename: String,
  source_code: String,
  maybe_output_code: Option<String>,
}

use std::error::Error;

fn code_fetch(
  module_specifier: &str,
  containing_file: &str,
) -> Result<CodeFetchOutput, Box<Error>> {
  let (module_name, filename) =
    resolve_module(module_specifier, containing_file)?;

  debug!(
        "code_fetch. module_name = {} module_specifier = {} containing_file = {} filename = {}",
        module_name, module_specifier, containing_file, filename
    );

  let out = get_source_code(module_name.as_str(), filename.as_str()).and_then(
    |source_code| {
      Ok(CodeFetchOutput {
        module_name,
        filename,
        source_code,
        maybe_output_code: None,
      })
    },
  )?;

  let result =
    deno_dir::load_cache(out.filename.as_str(), out.source_code.as_str());
  match result {
    Err(err) => {
      if err.kind() == std::io::ErrorKind::NotFound {
        Ok(out)
      } else {
        Err(err.into())
      }
    }
    Ok(output_code) => Ok(CodeFetchOutput {
      module_name: out.module_name,
      filename: out.filename,
      source_code: out.source_code,
      maybe_output_code: Some(output_code),
    }),
  }
}

// https://github.com/ry/deno/blob/golang/os.go#L100-L154
#[no_mangle]
pub extern "C" fn handle_code_fetch(
  d: *const DenoC,
  cmd_id: u32,
  module_specifier_: *const c_char,
  containing_file_: *const c_char,
) {
  let module_specifier = str_from_ptr!(module_specifier_);
  let containing_file = str_from_ptr!(containing_file_);

  let result = code_fetch(module_specifier, containing_file).map_err(|err| {
    let errmsg = format!("{}", err);
    reply_error(d, cmd_id, &errmsg);
  });
  if result.is_err() {
    return;
  }
  let out = result.unwrap();
  // reply_code_fetch
  let mut builder = flatbuffers::FlatBufferBuilder::new();
  let mut msg_args = msg::CodeFetchResArgs {
    module_name: builder.create_string(&out.module_name),
    filename: builder.create_string(&out.filename),
    source_code: builder.create_string(&out.source_code),
    ..Default::default()
  };
  match out.maybe_output_code {
    Some(ref output_code) => {
      msg_args.output_code = builder.create_string(output_code);
    }
    _ => (),
  };
  let msg = msg::CreateCodeFetchRes(&mut builder, &msg_args);
  builder.finish(msg);
  let args = msg::BaseArgs {
    cmdId: cmd_id,
    msg: Some(msg.union()),
    msg_type: msg::Any::CodeFetchRes,
    ..Default::default()
  };
  set_response_base(d, &mut builder, &args)
}

fn is_remote(_module_name: &str) -> bool {
  false
}

// https://github.com/ry/deno/blob/golang/os.go#L156-L169
#[no_mangle]
pub extern "C" fn handle_code_cache(
  d: *const DenoC,
  cmd_id: u32,
  filename_: *const c_char,
  source_code_: *const c_char,
  output_code_: *const c_char,
) {
  let filename = str_from_ptr!(filename_);
  let source_code = str_from_ptr!(source_code_);
  let output_code = str_from_ptr!(output_code_);
  let result = code_cache(filename, source_code, output_code);
  if result.is_err() {
    let err = result.unwrap_err();
    let errmsg = format!("{}", err);
    reply_error(d, cmd_id, &errmsg);
  }
  // null response indicates success.
}

use std::io::Write;
fn code_cache(
  filename: &str,
  source_code: &str,
  output_code: &str,
) -> std::io::Result<()> {
  deno_dir::setup()?;
  let cache_path = deno_dir::cache_path(filename, source_code);
  if cache_path.exists() {
    return Ok(());
  }
  let mut file = File::create(cache_path)?;
  file.write_all(output_code.as_bytes())?;
  Ok(())
}

#[test]
fn test_code_cache() {
  deno_dir::reset().expect("deno_dir::reset error");

  let filename = "hello.js";
  let source_code = "1+2";
  let output_code = "1+2 // output code";
  let cache_path = deno_dir::cache_path(filename, source_code);
  assert!(
    cache_path.ends_with("gen/e8e3ee6bee4aef2ec63f6ec3db7fc5fdfae910ae.js")
  );

  let r = code_cache(filename, source_code, output_code);
  r.expect("code_cache error");
  assert!(cache_path.exists());
  assert_eq!(output_code, fs::read_file_sync(&cache_path).unwrap());
}
