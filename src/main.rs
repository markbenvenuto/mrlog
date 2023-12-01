// Copyright [2020] [Mark Benvenuto]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(target_os = "linux")]
extern crate addr2line;
extern crate cpp_demangle;
extern crate crossbeam_channel;
extern crate ctrlc;
extern crate json;
#[cfg(target_os = "linux")]
extern crate memmap2;
#[cfg(target_os = "linux")]
extern crate object;
extern crate regex;

// TODO - make mac and linux specific
#[cfg(not(target_os = "windows"))]
extern crate nix;
#[cfg(not(target_os = "windows"))]
use nix::sys::signal::{self, Signal};
#[cfg(not(target_os = "windows"))]
use nix::unistd::Pid;

#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, Cursor, ErrorKind, Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::rc::Rc;
use std::string::String;
use std::string::ToString;
use std::thread;
use std::vec::Vec;
use std::{borrow::Cow, fs};

use anyhow::{Context, Result};

use cpp_demangle::Symbol;

#[cfg(target_os = "linux")]
use object::Object;

use colored::control::SHOULD_COLORIZE;
use colored::{ColoredString, Colorize};

use lazy_regex::{lazy_regex, Lazy};
use regex::*;

use structopt::StructOpt;

mod shared_stream;
use shared_stream::SharedStreamFactory;

// See https://stackoverflow.com/questions/32300132/why-cant-i-store-a-value-and-a-reference-to-that-value-in-the-same-struct
#[cfg(target_os = "linux")]
mod rent {
    use ouroboros::self_referencing;
    use std::rc::Rc;

    #[self_referencing]
    pub struct RentObject {
        lib: Rc<memmap2::Mmap>,

        #[borrows(lib)]
        #[covariant]
        obj: Rc<object::File<'this>>,

        #[borrows(obj)]
        #[covariant]
        sym: Rc<object::SymbolMap<object::SymbolMapName<'this>>>,
    }

    // Since the new and other functions are not public, we have to overcome E0624 with this hack
    pub fn call_new(
        lib: Rc<memmap2::Mmap>,
        obj_builder: impl for<'this> ::core::ops::FnOnce(
            &'this Rc<memmap2::Mmap>,
        ) -> Rc<object::File<'this>>,
        sym_builder: impl for<'this> ::core::ops::FnOnce(
            &'this Rc<object::File<'this>>,
        ) -> Rc<
            object::SymbolMap<object::SymbolMapName<'this>>,
        >,
    ) -> RentObject {
        RentObject::new(lib, obj_builder, sym_builder)
    }

    pub fn call_with_obj<'outer_borrow, ReturnType>(
        ro: &'outer_borrow RentObject,
        user: impl for<'this> ::core::ops::FnOnce(&'outer_borrow Rc<object::File<'this>>) -> ReturnType,
    ) -> ReturnType {
        ro.with_obj(user)
    }

    pub fn call_with_sym<'outer_borrow, ReturnType>(
        ro: &'outer_borrow RentObject,

        user: impl for<'this> ::core::ops::FnOnce(
            &'outer_borrow Rc<object::SymbolMap<object::SymbolMapName<'this>>>,
        ) -> ReturnType,
    ) -> ReturnType {
        ro.with_sym(user)
    }
}

struct LogFormatter {
    use_color: bool,
    log_id: bool,
    decode: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    objs: HashMap<String, rent::RentObject>,
    #[cfg(target_os = "linux")]
    ctxs: HashMap<String, addr2line::Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>>,
}

static LOG_FORMAT_PREFIX: &str = r#"{"t":{"$date"#;

static LOG_ERROR_REGEX: Lazy<Regex> =
    lazy_regex!(r#"invariant|fassert|failed to load|uncaught exception|FAIL"#);

// Unit tests
static LOG_WARNING_REGEX: Lazy<Regex> = lazy_regex!(r#"Expected"#);

static LOG_ATTR_REGEX: Lazy<Regex> = lazy_regex!(r#"\{([\w]+)\}"#);

//static LOG_PORT_REGEX: Lazy<Regex> = lazy_regex!(r#" [sdbc](\d{1,5})\|"#);

//static LOG_STATE_REGEX: Lazy<Regex> = lazy_regex!(r#"\[j\d:([cs]\d?)?(:prim|:sec)?\]"#);
// r#"(:s(hard)?\d*|:c(onfigsvr)?)?:(initsync|prim(ary)?|(mongo)?s|sec(ondary)?\d*|n(ode)?\d*)]"#;

// from duration.h
const LOG_TIME_SUFFIXES_TUPLE: &[(&str, &str)] = &[
    ("Nanos", "ns"),
    ("Micros", "μs"), // GREEK SMALL LETTER MU, 0x03BC or 956 code point
    ("Millis", "ms"),
    ("Seconds", "s"),
    ("Minutes", "min"),
    ("Hours", "hr"),
    ("Days", "d"),
];

// Color list from lobster
//const COLOR_LIST: &'static [i32] = &[
//    0x5aae61, 0x9970ab, 0xbf812d, 0x2166ac, 0x8c510a, 0x1b7837, 0x74add1, 0xd6604d, 0x762a83,
//    0x35978f, 0xde77ae,
//];

fn get_json_str<'a>(v: &'a json::JsonValue, name: &str, line: &str) -> Result<&'a str> {
    let r = v[name]
        .as_str()
        .with_context(|| format!("Failed to find '{}' in JSON log line: {}", name, line))?;
    Ok(r)
}

fn color_test_suite(s: &str) -> ColoredString {
    s.truecolor(108, 68, 171).bold()
}

fn color_test_name(s: &str) -> ColoredString {
    s.truecolor(47, 138, 173)
}

fn color_function_address(s: &str) -> ColoredString {
    s.blue()
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
struct ObjectEntry {
    binary: String,
    build_id: String,
    path: Option<String>,
}

// The shape of the somap varies per platform
// Windows has none
// Linux
//   "path": "file_path",  // path to file
//   "elfType": 2,         // 2 for binary, 3 for .so
//   "b": "10E24B000",     // binary load address
//   "buildId": "D05565997E393D45B628A76CCBBA5291"
// Mac
//   "path": "file_path",  // path to file
//   "machType": 2,        // 2 for binary, 6 for .dylib
//   "b": "10E24B000",     // binary load address
//   "vmaddr": "100000000", // ?
//   "buildId": "D05565997E393D45B628A76CCBBA5291"
#[cfg(target_os = "linux")]
fn parse_somap(o: &json::JsonValue) -> Result<HashMap<String, ObjectEntry>> {
    let mut map = HashMap::new();
    if o.is_array() {
        for i in o.members() {
            let binary = get_json_str(i, "b", "")?;
            let build_id = get_json_str(i, "buildId", "")?;
            let path = i["path"].as_str();

            map.insert(
                binary.to_string(),
                ObjectEntry {
                    binary: binary.to_string(),
                    build_id: build_id.to_string(),
                    path: path.map(|x| x.to_string()),
                },
            );
        }
    }

    Ok(map)
}

impl LogFormatter {
    fn new(use_color: bool, log_id: bool, decode: Option<PathBuf>) -> LogFormatter {
        LogFormatter {
            use_color,
            log_id,
            decode,
            #[cfg(target_os = "linux")]
            ctxs: HashMap::new(),
            #[cfg(target_os = "linux")]
            objs: HashMap::new(),
        }
    }

    #[cfg(test)]
    fn new_for_test() -> LogFormatter {
        LogFormatter {
            use_color: false,
            log_id: false,
            decode: None,
            #[cfg(target_os = "linux")]
            ctxs: HashMap::new(),
            #[cfg(target_os = "linux")]
            objs: HashMap::new(),
        }
    }

    fn format_line(
        &self,
        date: &str,
        log_level: &str,
        component: &str,
        context: &str,
        id: u64,
        msg: &str,
    ) -> String {
        if self.log_id {
            return format!(
                "{} {:<2} {:<8} {:<5} [{}] {}",
                date, log_level, component, id, context, msg
            );
        }
        LogFormatter::format_line_basic(date, log_level, component, context, msg)
    }

    fn format_line_basic(
        date: &str,
        log_level: &str,
        component: &str,
        context: &str,
        msg: &str,
    ) -> String {
        format!(
            "{} {:<2} {:<8} [{}] {}",
            date, log_level, component, context, msg
        )
    }

    fn maybe_color(&self, s: ColoredString) -> String {
        if !self.use_color {
            return s.clear().to_string();
        }

        s.to_string()
    }

    fn maybe_color_text<'a>(&self, s: &'a str) -> Cow<'a, str> {
        if !self.use_color {
            return Cow::from(s);
        }

        if LOG_ERROR_REGEX.is_match(s) {
            return Cow::Owned(s.truecolor(206, 30, 92).to_string());
        }

        if LOG_WARNING_REGEX.is_match(s) {
            return Cow::Owned(s.truecolor(223, 135, 46).to_string());
        }

        Cow::from(s)
    }

    fn demangle_frame<F>(
        &self,
        frame: &json::JsonValue,
        s: &str,
        line_formatter: F,
    ) -> Result<Option<String>>
    where
        F: Fn(&str) -> String,
    {
        // Windows: "msg":"  Frame: {frame}","attr":{"frame":{"a":"7FFCD7CAC3E1","module":"ucrtbased.dll","s":"raise","s+":"441"}}}
        //          "msg":"  Frame: {frame}","attr":{"frame":{"a":"7FF7FD471750","module":"util_test.exe","file":".../src/mongo/util/alarm_test.cpp","line":48,"s":"mongo::`anonymous namespace'::doThrow","s+":"30"}}}
        // Linux:   "msg":"  Frame: {frame}","attr":{"frame":{"a":"7F4266DD4CD5","b":"7F4266DA1000","o":"33CD5","s":"abort","s+":"175"}}}
        //          "msg":"Frame","attr":{"frame":{"a":"5585D6E3A6AB","b":"5585CDBFE000","o":"923C6AB"}}}
        let symbol_address = get_json_str(frame, "a", s)?;
        let symbol_module_ret = frame["module"].as_str();
        if let Some(symbol_module) = symbol_module_ret {
            let symbol_file_ret = frame["file"].as_str();
            let symbol_name = get_json_str(frame, "s", s)?;
            let symbol_offset = get_json_str(frame, "s+", s)?;

            if let Some(symbol_file) = symbol_file_ret {
                let symbol_line = frame["line"]
                    .as_u64()
                    .with_context(|| format!("Failed to find 'line' in JSON log line: {}", s))?;
                // Format as Windows with file and line
                return Ok(Some(line_formatter(
                    format!(
                        "  Frame: {} {}!{}+0x{} [{} @ {}]",
                        self.maybe_color(color_function_address(&format!("0x{}", symbol_address))),
                        symbol_module, // TODO - color this
                        self.maybe_color(symbol_name.yellow()),
                        symbol_offset,
                        symbol_file,
                        symbol_line
                    )
                    .as_ref(),
                )));
            } else {
                // Format as Windows
                return Ok(Some(line_formatter(
                    format!(
                        "  Frame: {} {}!{}+0x{}",
                        self.maybe_color(color_function_address(&format!("0x{}", symbol_address))),
                        symbol_module, // TODO - color this
                        self.maybe_color(symbol_name.yellow()),
                        symbol_offset
                    )
                    .as_ref(),
                )));
            }
        }

        let symbol_binary_ret = frame["b"].as_str();
        if let Some(_symbol_binary) = symbol_binary_ret {
            let binary_offset = get_json_str(frame, "o", s)?;

            let symbol_name_ret = frame["s"].as_str();
            // Format as Linux
            if let Some(symbol_name) = symbol_name_ret {
                let symbol_offset = get_json_str(frame, "s+", s)?;

                let mut sym_name = symbol_name.to_owned();

                // External demangled names are supposed to be prefixed with "_Z"
                if symbol_name.starts_with("_Z") {
                    let sr = Symbol::new(symbol_name);
                    match sr {
                        Err(_e) => {
                            // We cannot ignore C functions for instance so errors are expected
                            println!("WARNING: cannot demangle '{}' in {}", symbol_name, s);
                        }
                        Ok(sym) => sym_name = sym.to_string(),
                    }
                }

                return Ok(Some(line_formatter(
                    format!(
                        "  Frame: {} {}+0x{}",
                        self.maybe_color(color_function_address(&format!("0x{}", symbol_address))),
                        self.maybe_color(sym_name.yellow()),
                        symbol_offset
                    )
                    .as_ref(),
                )));
            } else {
                // No symbol name
                return Ok(Some(line_formatter(
                    format!(
                        "  Frame: {} +0x{}",
                        self.maybe_color(color_function_address(&format!("0x{}", symbol_address))),
                        binary_offset
                    )
                    .as_ref(),
                )));
            }
        }

        // fall through to print the raw string
        Ok(None)
    }

    #[cfg(target_os = "linux")]
    fn init_binary_context_if_needed(&mut self, path: &str) -> Result<()> {
        let ret = self.objs.contains_key(path);

        if !ret {
            let file = File::open(path)
                .with_context(|| format!("Failed to open file '{}' for dwarf and symbols", path))?;

            let m1 = unsafe {
                memmap2::Mmap::map(&file).with_context(|| {
                    format!("Failed to mmap file '{}' for dwarf and symbols", path)
                })?
            };
            let r1 = rent::call_new(
                Rc::new(m1),
                |m3| {
                    let s: &[u8] = m3.as_ref();
                    Rc::new(
                        object::File::parse(s)
                            .unwrap_or_else(|_| panic!("Failed to parse file '{}'", path)),
                    )
                },
                |a1| Rc::new(a1.symbol_map()),
            );

            self.objs.insert(path.to_string(), r1);
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn get_binary_context(
        &mut self,
        path: Option<&str>,
    ) -> Result<&addr2line::Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>> {
        let path_str = match path {
            Some(p) => p.to_owned(),
            None => self.decode.as_ref().unwrap().to_str().unwrap().to_owned(),
        };
        let path = &path_str;

        self.init_binary_context_if_needed(path)?;

        let ret = self.ctxs.contains_key(path);

        // TODO - use moria to find symbols - https://github.com/gimli-rs/moria
        // TODO - add support for split symbols
        if !ret {
            let o = self.objs.get(path).unwrap();

            let b2 = rent::call_with_obj(o, |x| addr2line::Context::new(x.as_ref()))?;

            self.ctxs.insert(path.to_string(), b2);
        }

        let ret2 = self.ctxs.get(path);
        Ok(ret2.unwrap())
    }

    #[cfg(target_os = "linux")]
    fn get_symbol_name(&self, path: &str, address: u64) -> String {
        let o = self.objs.get(path).unwrap();

        rent::call_with_sym(o, |x| match x.get(address) {
            Some(sym) => sym.name().to_owned(),
            None => format!("{}+<{:#x}>", path, address),
        })
    }

    #[cfg(target_os = "linux")]
    fn demangle_backtrace<F>(&mut self, bt: &json::JsonValue, line_formatter: F) -> Result<String>
    where
        F: Fn(&str) -> String,
    {
        let somap_json = &bt["processInfo"]["somap"];

        let somap = parse_somap(somap_json)?;
        let mut ret = String::new();

        // Each entry has the following shape:
        // "a": "5585D6E3D29F",
        // "b": "5585CDBFE000",
        // "o": "923F29F",
        // "s": "_ZN5mongo12rawBacktraceEPPvm", // Optional
        // "s+": "1F"  // Optional
        for i in bt["backtrace"].members() {
            let binary = get_json_str(i, "b", "")?;
            let _address = get_json_str(i, "a", "")?;
            let offset_orig = get_json_str(i, "o", "")?;

            let offset = u64::from_str_radix(offset_orig, 16)?;

            // TODO - remove unwrap
            // TODO - validate build ids here, lets not load wrong binaries unless asked by user
            let oe = somap.get(binary).unwrap();

            let ctx = self.get_binary_context(oe.path.as_deref())?;

            let mut count = 0;
            {
                let frames_result = ctx.find_frames(offset);

                // TODO - add support for split dwarf
                // see addr2line::builtin_split_dwarf_loader::SplitDwarfLoader
                let mut frames = frames_result.skip_all_loads()?;
                while let Some(frame) = frames.next()? {
                    count += 1;

                    match frame.location {
                        Some(loc) => {
                            std::fmt::Write::write_str(
                                &mut ret,
                                &line_formatter(&format!(
                                    "{} at {}:{}\n",
                                    frame.function.map_or_else(
                                        || format!("<unknown>+{}", offset_orig),
                                        |f| f
                                            .demangle()
                                            .unwrap_or_else(|_| Cow::Owned(format!(
                                                "demangle failed+{}",
                                                offset_orig
                                            )))
                                            .to_string()
                                    ),
                                    loc.file.unwrap_or("<unknown>"),
                                    loc.line.unwrap_or(0)
                                )),
                            )?;
                        }
                        None => {
                            std::fmt::Write::write_str(
                                &mut ret,
                                &line_formatter(&format!(
                                    "{}\n",
                                    frame.function.map_or_else(
                                        || format!("<unknown>+{}", offset_orig),
                                        |f| f
                                            .demangle()
                                            .unwrap_or_else(|_| Cow::Owned(format!(
                                                "demangle failed+{}",
                                                offset_orig
                                            )))
                                            .to_string()
                                    )
                                )),
                            )?;
                        }
                    }
                }
            }

            if count == 0 {
                let a = self.get_symbol_name(
                    oe.path
                        .as_ref()
                        .unwrap_or(&self.decode.as_ref().unwrap().to_str().unwrap().to_owned()),
                    offset,
                );
                std::fmt::Write::write_str(&mut ret, &line_formatter(&format!("{}\n", a)))?;
            }
        }

        Ok(ret)
    }

    #[cfg(not(target_os = "linux"))]
    fn demangle_backtrace<F>(&mut self, _bt: &json::JsonValue, _line_formatter: F) -> Result<String>
    where
        F: Fn(&str) -> String,
    {
        Ok(String::new())
    }

    fn filter_test_extra(&mut self, s: &str) -> Result<String> {
        let mut string_buffer = String::with_capacity(s.len());
        let lines = s.lines();
        for line in lines {
            if line.starts_with("unw_get_proc_name") && line.ends_with("no unwind info found") {
                continue;
            }

            if let Some(fstr) = line.strip_prefix("  Frame:") {
                let parsed = json::parse(fstr)
                    .with_context(|| format!("Failed to parse JSON log line: {}", s))?;

                let frame_str_opt = self.demangle_frame(&parsed, s, |x| x.to_string())?;

                if let Some(frame_str) = frame_str_opt {
                    string_buffer.push_str(&frame_str);
                    string_buffer.push('\n');
                    continue;
                }
            }

            string_buffer.push_str(line);
            string_buffer.push('\n');
        }

        Ok(string_buffer)
    }

    fn unittest_exception_to_str<F>(
        &mut self,
        s: &str,
        attr: &json::JsonValue,
        line_formatter: F,
    ) -> Result<String>
    where
        F: Fn(&str) -> String,
    {
        let mut ret = String::new();

        let test_name = get_json_str(attr, "test", s)?;
        let test_exception = get_json_str(attr, "type", s)?;
        let test_error = get_json_str(attr, "error", s)?;

        // This is a string dump of an json document of a stack trace
        let test_extra = get_json_str(attr, "extra", s)?;
        std::fmt::Write::write_str(
            &mut ret,
            &line_formatter(
                self.maybe_color_text(&format!("UNIT TEST FAILURE: '{}'\n", test_name))
                    .as_ref(),
            ),
        )?;

        std::fmt::Write::write_str(
            &mut ret,
            &line_formatter(
                self.maybe_color_text(&format!("Exception: '{}'\n", test_exception))
                    .as_ref(),
            ),
        )?;

        // Add a space after @ to be friendlier for vs code
        let fixed_test_error = test_error.replace("@src", "@ src");

        std::fmt::Write::write_str(
            &mut ret,
            &line_formatter(
                self.maybe_color_text(&format!("Message: {}\n", fixed_test_error))
                    .as_ref(),
            ),
        )?;
        std::fmt::Write::write_str(
            &mut ret,
            &line_formatter(&(self.filter_test_extra(test_extra)?)),
        )?;

        Ok(ret)
    }

    fn log_to_str(&mut self, s: &str) -> Result<String> {
        let parsed =
            json::parse(s).with_context(|| format!("Failed to parse JSON log line: {}", s))?;

        let d = parsed["t"]["$date"]
            .as_str()
            .with_context(|| format!("Failed to find 't.$date' in JSON log line: {}", s))?;
        let log_level = get_json_str(&parsed, "s", s)?;
        let component = get_json_str(&parsed, "c", s)?;
        let log_id = parsed["id"]
            .as_u64()
            .with_context(|| format!("Failed to find 'id' in JSON log line: {}", s))?;
        let context = get_json_str(&parsed, "ctx", s)?;
        let msg = get_json_str(&parsed, "msg", s)?;
        let attr = &parsed["attr"];

        let line_formatter =
            |x: &str| self.format_line(d, log_level, component, context, log_id, x);
        let basic_line_formatter =
            |x: &str| LogFormatter::format_line_basic(d, log_level, component, context, x);

        if msg.contains('{') {
            // Handle messages which are just an empty {}
            if msg == "{}" {
                return Ok(self.format_line(
                    d,
                    log_level,
                    component,
                    context,
                    log_id,
                    self.maybe_color_text(attr["message"].as_str().with_context(|| {
                        format!("Failed to find 'message' in JSON log line: {}", s)
                    })?)
                    .as_ref(),
                ));
            }

            let is_frame = msg.starts_with("  Frame:") || msg.starts_with("Frame");
            if is_frame {
                let frame_str_opt = self.demangle_frame(&attr["frame"], s, line_formatter)?;
                if let Some(frame_str) = frame_str_opt {
                    return Ok(frame_str);
                }
            }

            let msg_fmt = LOG_ATTR_REGEX.replace_all(msg, |caps: &Captures| {
                // println!("{}", &caps[1]);
                let v = &attr[&caps[1]];
                if v.is_object() || v.is_number() || v.is_boolean() {
                    return v.dump();
                }
                let r = v.as_str();
                if r.is_none() {
                    // duration attributes are automatically suffixed when written to json so they
                    // differ from key in the replacement string so try all the known suffixes
                    for (suffix, short) in LOG_TIME_SUFFIXES_TUPLE {
                        let key = String::from(&caps[1]) + suffix;
                        let v = &attr[key];
                        if v.is_number() {
                            return v.dump() + short;
                        }
                    }

                    println!("WARNING: no str attr for '{}' in {}", &caps[1], s);
                    return String::from("unknown");
                }
                String::from(r.unwrap())
            });

            Ok(self.format_line(
                d,
                log_level,
                component,
                context,
                log_id,
                self.maybe_color_text(&msg_fmt).as_ref(),
            ))
        } else {
            if !attr.is_empty() {
                // Only mac and linux have processInfo
                // Note: decoding only works on Linux for now since gimli::Object does not support multi-arch binaries on Mac
                // TODO - use goblin instead
                // See https://github.com/rust-lang/backtrace-rs/blob/ac175e25d15e7bd2c870cd4d06e141bc62bbf59e/src/symbolize/gimli.rs#L38-L61
                if cfg!(target_os = "linux")
                    && self.decode.is_some()
                    && msg.starts_with("BACKTRACE")
                    && attr["bt"].has_key("processInfo")
                    && attr["bt"]["processInfo"]["somap"][0].has_key("elfType")
                {
                    return self.demangle_backtrace(&attr["bt"], basic_line_formatter);
                }

                let is_frame = msg.starts_with("  Frame:") || msg.starts_with("Frame");
                if is_frame {
                    let frame_str_opt = self.demangle_frame(&attr["frame"], s, line_formatter)?;
                    if let Some(frame_str) = frame_str_opt {
                        return Ok(frame_str);
                    }
                }

                // {"t":{"$date":"2022-06-23T20:26:51.713Z"},"s":"E",  "c":"TEST",
                //  "id":23070,
                // "ctx":"thread1",
                // "msg":"Throwing exception",
                // "attr":{"exception":"Expected swDoc.getValue().count == 12345689 (123456789 == 12345689) @src/mongo/crypto/fle_crypto_test.cpp:352"}}
                if log_id == 23070 {
                    let exception_text = get_json_str(attr, "exception", s)?;
                    // Add a space after @ to be friendlier for vs code
                    let fixed_msg = &exception_text.replace("@src", "@ src");
                    let s = String::from(msg) + " " + fixed_msg;
                    return Ok(line_formatter(&self.maybe_color_text(&s)));
                }

                // A message for a unit test failure
                if log_id == 4680100 {
                    return self.unittest_exception_to_str(s, attr, basic_line_formatter);
                }

                let s = String::from(msg) + " " + attr.dump().as_ref();

                // A message for a test suite
                // {"t":{"$date":"2022-06-23T20:26:51.825Z"},"s":"I",  "c":"TEST",     "id":23063,   "ctx":"thread1","msg":"Running","attr":{"suite":"FLE_ESC"}}
                if log_id == 23063 {
                    return Ok(self.format_line(
                        d,
                        log_level,
                        component,
                        context,
                        log_id,
                        self.maybe_color(color_test_suite(&s)).as_ref(),
                    ));
                }

                // A message for a test name
                // {"t":{"$date":"2022-06-23T20:26:51.825Z"},"s":"I",  "c":"TEST",     "id":23059,   "ctx":"thread1","msg":"Running","attr":{"test":"RoundTrip","rep":1,"reps":1}}
                if log_id == 23059 {
                    return Ok(self.format_line(
                        d,
                        log_level,
                        component,
                        context,
                        log_id,
                        self.maybe_color(color_test_name(&s)).as_ref(),
                    ));
                }

                return Ok(self.format_line(
                    d,
                    log_level,
                    component,
                    context,
                    log_id,
                    self.maybe_color_text(&s).as_ref(),
                ));
            }

            Ok(self.format_line(
                d,
                log_level,
                component,
                context,
                log_id,
                self.maybe_color_text(msg).as_ref(),
            ))
        }
    }

    fn fuzzy_log_to_str(&mut self, s: &str) -> Result<String> {
        if s.starts_with(LOG_FORMAT_PREFIX) {
            return self.log_to_str(s);
        }

        // TODO - become stateful and rember where we found a previous start
        let f = s.find(LOG_FORMAT_PREFIX);
        if let Some(pos) = f {
            let end = self.log_to_str(s[pos..s.len()].as_ref())?;
            return Ok(String::from(&s[0..pos]) + end.as_ref());
        }

        // We do not think it is a JSON log line, return it as is
        Ok(String::from(s))
    }

    fn fuzzy_log_color_str(&mut self, s: &str) -> Result<String> {
        let ret_str = self.fuzzy_log_to_str(s)?;

        // let state_caps_opt = self.re_state_color.captures(&ret_str);
        // if let Some(state_caps) = state_caps_opt {
        //     let port = state_caps[1];
        // }

        Ok(ret_str)
    }
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn convert_lines<T>(lf: &mut LogFormatter, lines: T, writer: &mut dyn io::Write)
where
    T: Iterator<Item = io::Result<String>>,
{
    let lf_byte = vec![10];

    for line in lines.flatten() {
        let convert_result = lf.fuzzy_log_color_str(line.as_str());
        match convert_result {
            Ok(s) => {
                let r = writer.write_all(s.as_bytes());
                if r.is_err() {
                    eprintln!("convert_lines ok Error: {:?}", r);
                    return;
                }
            }
            Err(m) => {
                // TODO - format error message better
                let r = writer.write_all(m.to_string().as_bytes());
                if r.is_err() {
                    eprintln!("convert_lines error Error: {:?}", r);
                    return;
                }
            }
        }
        let r = writer.write_all(lf_byte.as_ref());
        if r.is_err() {
            eprintln!("convert_lines lf Error: {:?}", r);
            return;
        }
    }
}

#[derive(StructOpt)]
/// Convertes MongoDB 4.4 JSON log format to text format. Writes converted file to stdout
struct Cli {
    /// Optional path to the file to read, defaults to stdin
    /// In execute mode, a command to run and a list of args
    path_or_cmd: Option<String>,

    /// Args to run command with
    #[structopt(last = true)]
    cmd_args: Vec<String>,

    // Color output - errors are red
    #[structopt(short, long)]
    color: bool,

    /// Log id in text log
    #[structopt(long)]
    id: bool,

    /// Execute command and process output
    #[structopt(short, long)]
    execute: bool,

    /// Output file, stdout if not present
    #[structopt(short, long, parse(from_os_str))]
    output: Option<PathBuf>,

    /// If a output file alread exists, rename with .bak suffix
    #[structopt(long)]
    backup: bool,

    /// Tee ouput to output file and stdout
    #[structopt(short, long)]
    tee: bool,

    /// Decode backtraces with DWARF information from binary, split symbols not supported
    #[structopt(short, long, parse(from_os_str))]
    decode: Option<PathBuf>,
}

fn read_one(cur: &mut Cursor<&[u8]>) -> Option<u8> {
    let mut cb = [0; 1];

    let cr = cur.read_exact(&mut cb);
    if cr.is_err() {
        if cr.err().unwrap().kind() == ErrorKind::UnexpectedEof {
            return None;
        }

        // return cr.with_context(|| return "strip color failed");
        //return Err(anyhow::Error::msg("strip color failed"));
        // Err("TODO");
        // return anyhow!("...");
        panic!("strip color failed");
    }

    Some(cb[0])
}

// TODO - strip out ANSI codes when writing to a file.
// see https://en.wikipedia.org/wiki/ANSI_escape_code
// We need to look for "\x1B[" some text and then 'm'
fn strip_color(buf: &[u8], out_buf: &mut Vec<u8>) {
    out_buf.clear();
    out_buf.reserve(buf.len());

    if !buf.contains(&0x1B) {
        out_buf.extend_from_slice(buf);
        return;
    }

    let mut cur = Cursor::new(buf);

    loop {
        let b_esc_opt = read_one(&mut cur);
        if b_esc_opt.is_none() {
            return;
        }

        let b_esc = b_esc_opt.unwrap();
        if b_esc != 0x1B {
            out_buf.push(b_esc);
            continue;
        }

        // Parse '['
        let b_left_bracket_opt = read_one(&mut cur);
        if b_left_bracket_opt.is_none() {
            // TODO - unexpected
            eprintln!("Unterminated color code1, no '[' found");
            return;
        }

        let b_left_bracket = b_left_bracket_opt.unwrap();
        if b_left_bracket != b'[' {
            eprintln!("Unterminated color code2, no '[' found");
            out_buf.push(b_left_bracket);
            continue;
        }

        // Keep reading until 'm'
        loop {
            // Parse '['
            let b_trailing_m = read_one(&mut cur);
            if b_trailing_m.is_none() {
                // TODO - unexpected, unterminated code
                eprintln!("Unterminated color code, no 'm' found");
                return;
            }

            let b_trailing_m = b_trailing_m.unwrap();
            if b_trailing_m == b'm' {
                break;
            }
        }
    }
}

// Writer that strips all ASCII color codes from input stream
struct ColorStripperWriter<'a> {
    writer: Box<dyn io::Write + 'a>,
    buf: Vec<u8>,
}

impl<'a> ColorStripperWriter<'a> {
    fn new(writer: Box<dyn io::Write + 'a>) -> ColorStripperWriter<'a> {
        ColorStripperWriter {
            writer,
            buf: Vec::new(),
        }
    }
}

impl<'a> io::Write for ColorStripperWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        strip_color(buf, &mut self.buf);
        self.writer.write_all(self.buf.as_ref())?; // TODO error

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

struct TeeWriter<'a> {
    writers: Vec<Box<dyn io::Write + 'a>>,
}

impl<'a> TeeWriter<'a> {
    fn new(writers: Vec<Box<dyn io::Write + 'a>>) -> TeeWriter<'a> {
        TeeWriter { writers }
    }
}

impl<'a> io::Write for TeeWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut size: usize = 0;
        for writer in self.writers.iter_mut() {
            let s = writer.write(buf)?;
            if s != 0 && size != 0 && size != s {
                panic!("Failed to write same size to writers - {} - {}", s, size);
            }
            size = s;
        }
        Ok(size)
    }

    fn flush(&mut self) -> io::Result<()> {
        for writer in self.writers.iter_mut() {
            let r = writer.flush();

            #[allow(clippy::question_mark)]
            if r.is_err() {
                return r;
            }
        }
        Ok(())
    }
}

fn get_writer<'a>(
    file_name_buf: Option<PathBuf>,
    stdout: &'a io::Stdout,
    tee: bool,
    backup: bool,
    color_strip: bool,
) -> Result<Box<dyn io::Write + 'a>> {
    let mut writer: Box<dyn io::Write + 'a> =
        match file_name_buf.as_ref() {
            Some(file_name) => {
                if backup && file_name.as_path().exists() {
                    let new_file_str = format!("{}.bak", file_name.as_path().display());
                    let new_file = Path::new(&new_file_str);
                    fs::rename(file_name, new_file)?;
                }

                Box::new(File::create(file_name).with_context(|| {
                    format!("Failed to open file '{:#?}' for output", file_name)
                })?)
            }

            None => {
                // TODO - throw error if tee == true

                let out_lock = stdout.lock();
                Box::new(out_lock)
            }
        };

    if tee {
        if color_strip {
            writer = Box::new(ColorStripperWriter::new(writer));
        }

        let mut writers = vec![writer];

        let out_lock = stdout.lock();
        writers.push(Box::new(out_lock));

        Ok(Box::new(TeeWriter::new(writers)))
    } else {
        Ok(writer)
    }
}

#[cfg(not(target_os = "windows"))]
fn send_ctrl_c(pid: i32) {
    // Send SIGINT to child process to trigger Ctrl-C
    signal::kill(Pid::from_raw(pid), Signal::SIGINT).unwrap();
}

#[cfg(target_os = "windows")]
fn send_ctrl_c(pid: i32) {
    // TODO - untested if this kills mrlog or just the child process
    unsafe {
        winapi::um::wincon::GenerateConsoleCtrlEvent(winapi::um::wincon::CTRL_C_EVENT, pid as u32);
    }
}

fn run_command(
    cmd: &str,
    cmd_args: &[String],
    lf: &mut LogFormatter,
    writer: &mut dyn io::Write,
) -> Result<()> {
    let mut builder = Command::new(cmd);
    for arg in cmd_args {
        builder.arg(arg);
    }

    let child = builder
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let child_id = child.id() as i32;
    ctrlc::set_handler(move || {
        eprintln!("mrlog received Ctrl+C!");

        // Send SIGINT to child process to trigger Ctrl-C
        send_ctrl_c(child_id);

        // TODO - wait for exit
        // child.wait();
        // Sleep for now and hope the child process exists
        thread::sleep(std::time::Duration::from_secs(120));
    })?;

    let ssf = SharedStreamFactory::new();
    let mut stdout_writer = ssf.get_writer();

    let mut stderr_writer = ssf.get_writer();

    let mut output_out = child
        .stdout
        .ok_or("Failed to open child pipe's stdout")
        .unwrap();
    let mut output_err = child
        .stderr
        .ok_or("Failed to open child pipe's stderr")
        .unwrap();

    let ts = thread::spawn(move || {
        let mut v = vec![0; 8192];

        loop {
            let ret = output_out.read(v.as_mut_slice());
            match ret {
                Ok(size) => {
                    if size == 0 {
                        break;
                    }
                    let r = stdout_writer.write_all(&v.as_slice()[0..size]);
                    if r.is_err() {
                        eprintln!("Unexpected error writing to standard out writer {:?}", r);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Unexpected error reading from standard out {:?}", e);
                    break;
                }
            };
        }
    });

    let ts2 = thread::spawn(move || {
        let mut v = vec![0; 8192];

        loop {
            let ret = output_err.read(v.as_mut_slice());
            match ret {
                Ok(size) => {
                    if size == 0 {
                        break;
                    }
                    let r = stderr_writer.write_all(&v.as_slice()[0..size]);
                    if r.is_err() {
                        eprintln!("Unexpected error writing to standard err writer {:?}", r);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Unexpected error reading from standard err {:?}", e);
                    break;
                }
            };
        }
    });

    let std_reader = ssf.get_reader();

    let lines = io::BufReader::new(std_reader).lines();
    convert_lines(lf, lines, writer);

    ts.join().unwrap();
    ts2.join().unwrap();

    Ok(())
}

fn main() -> Result<()> {
    let args = Cli::from_args();

    if args.color {
        SHOULD_COLORIZE.set_override(true);
    }

    let stdout_handle = io::stdout();
    let mut writer = get_writer(
        args.output,
        &stdout_handle,
        args.tee,
        args.backup,
        args.color,
    )?;

    let mut lf = LogFormatter::new(args.color, args.id, args.decode);

    if args.execute & args.path_or_cmd.is_some() {
        let cmd = &args.path_or_cmd.unwrap();
        let cmd_args = args.cmd_args;

        run_command(cmd, &cmd_args, &mut lf, &mut writer)?
    } else {
        match args.path_or_cmd {
            Some(file_name) => {
                let p = std::path::PathBuf::from(file_name);
                let lines = read_lines(p)?;

                convert_lines(&mut lf, lines, &mut writer);
            }
            None => {
                let stdin = io::stdin();
                let handle_in = stdin.lock();

                let lines = io::BufReader::new(handle_in).lines();
                convert_lines(&mut lf, lines, &mut writer);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
fn strip_color_to_buf(buf: &[u8]) -> Vec<u8> {
    let mut out_buf = Vec::new();
    strip_color(buf, &mut out_buf);
    out_buf
}

#[test]
fn test_log_to_str() {
    let mut lf = LogFormatter::new_for_test();

    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":20533,"ctx":"initandlisten","msg":"DEBUG build (which is slower)"}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] DEBUG build (which is slower)"};
}

#[test]
fn test_log_to_str_with_replacements() {
    let mut lf = LogFormatter::new_for_test();
    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"{openSSLVersion_OpenSSL_version}","attr":{"openSSLVersion_OpenSSL_version":"OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"}}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"};

    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"test {test1}","attr":{"test1":123}}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] test 123"};

    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"test {test1}","attr":{"test1":{"abc":123}}}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] test {\"abc\":123}"};

    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-04-06T16:34:32.964-04:00"},"s":"I", "c":"STORAGE", "id":46712010,"ctx":"initandlisten","msg":"should read at last applied. {val}","attr":{"val":true}}"#).unwrap(), "2020-04-06T16:34:32.964-04:00 I  STORAGE  [initandlisten] should read at last applied. true"};
}

#[test]
fn test_log_to_str_with_duration_replacements() {
    let mut lf = LogFormatter::new_for_test();
    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"test {duration}","attr":{"durationMillis":123}}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] test 123ms"};

    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"test {duration}","attr":{"durationMicros":123}}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] test 123μs"};

    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-04-08T11:49:08.243-04:00"},"s":"I", "c":"-",       "id":4333222,"ctx":"ReplicaSetMonitor-TaskExecutor","msg":"RSM {setName} received failed isMaster for server {host}: {status} ({latency}): {bson}","attr":{"host":"chimichurri:20022","status":"NetworkInterfaceExceededTimeLimit: Couldn't get a connection within the time limit of 1000ms","latencyNanos":9999952000,"setName":"config_chunks_tags_upgrade_downgrade_cluster-rs0","bson":"{}"}}"#).unwrap(), "2020-04-08T11:49:08.243-04:00 I  -        [ReplicaSetMonitor-TaskExecutor] RSM config_chunks_tags_upgrade_downgrade_cluster-rs0 received failed isMaster for server chimichurri:20022: NetworkInterfaceExceededTimeLimit: Couldn\'t get a connection within the time limit of 1000ms (9999952000ns): {}"};
}

#[test]
fn test_fuzzy_log() {
    let mut lf = LogFormatter::new_for_test();
    assert_eq! { lf.fuzzy_log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"{openSSLVersion_OpenSSL_version}","attr":{"openSSLVersion_OpenSSL_version":"OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"}}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"};

    assert_eq! { lf.fuzzy_log_to_str(r#"[js_test:txn_two_phase_commit_basic] 2020-02-15T23:32:14.540-0500 d20021| {"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL","id":23400,"ctx":"initandlisten","msg":"{openSSLVersion_OpenSSL_version}","attr":{"openSSLVersion_OpenSSL_version":"OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"}}"#).unwrap(), "[js_test:txn_two_phase_commit_basic] 2020-02-15T23:32:14.540-0500 d20021| 2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"};
}

#[test]
fn test_demangle() {
    let mut lf = LogFormatter::new_for_test();

    // gdb formatting
    // #2  __pthread_cond_timedwait (cond=0x7ffff56f2b30, mutex=0x7ffff56975b0, abstime=0x7ffff3a0a470) at pthread_cond_wait.c:656
    // #3  0x000055555ab43bc5 in __gthread_cond_timedwait (__cond=0x7ffff56f2b30, __mutex=0x7ffff56975b0, __abs_timeout=0x7ffff3a0a470) at /usr/bin/../lib/gcc/x86_64-redhat-linux/9/../../../../include/c++/9/x86_64-redhat-linux/bits/gthr-default.h:872

    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-03-27T22:14:14.256Z"},"s":"I", "c":"CONTROL", "id":31427,  "ctx":"main","msg":"  Frame: {frame}","attr":{"frame":{"a":"7F426A9EE7E6","b":"7F4268D16000","o":"1CD87E6","s":"_ZN5mongo12_GLOBAL__N_116abruptQuitActionEiP7siginfoPv","s+":"66"}}}"#).unwrap(), "2020-03-27T22:14:14.256Z I  CONTROL  [main]   Frame: 0x7F426A9EE7E6 mongo::(anonymous namespace)::abruptQuitAction(int, siginfo*, void*)+0x66"};

    // Windows demangles for us

    // Windows formatting
    // 02 0000009a`84bfea50 00007ffc`9321c937 KERNELBASE!SleepConditionVariableSRW+0x2d
    // 03 0000009a`84bfea90 00007ffc`931e1466 MSVCP140D!__crtSleepConditionVariableSRW+0x67 [f:\dd\vctools\crt\crtw32\misc\winapisupp.cpp @ 626]
    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-03-26T20:22:29.422Z"},"s":"I", "c":"CONTROL", "id":31445,  "ctx":"main","msg":"  Frame: {frame}","attr":{"frame":{"a":"7FFCD7CAC3E1","module":"ucrtbased.dll","s":"raise","s+":"441"}}}"#).unwrap(), "2020-03-26T20:22:29.422Z I  CONTROL  [main]   Frame: 0x7FFCD7CAC3E1 ucrtbased.dll!raise+0x441"};

    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-03-26T20:22:29.422Z"},"s":"I", "c":"CONTROL", "id":31445,  "ctx":"main","msg":"  Frame: {frame}","attr":{"frame":{"a":"7FF7FD471783","module":"util_test.exe","file":".../src/mongo/util/alarm_test.cpp","line":53,"s":"mongo::`anonymous namespace'::UnitTest_SuiteNameAlarmSchedulerTestNameBrokeAss::_doTest","s+":"23"}}}"#).unwrap(), "2020-03-26T20:22:29.422Z I  CONTROL  [main]   Frame: 0x7FF7FD471783 util_test.exe!mongo::`anonymous namespace\'::UnitTest_SuiteNameAlarmSchedulerTestNameBrokeAss::_doTest+0x23 [.../src/mongo/util/alarm_test.cpp @ 53]"};
}

#[test]
fn test_color_strip() {
    assert_eq! {strip_color_to_buf("abc".as_bytes()), "abc".as_bytes()}

    assert_eq! {strip_color_to_buf("abc\x1b[0m".as_bytes()), "abc".as_bytes()}

    assert_eq! {strip_color_to_buf("abc\x1b[0m".as_bytes()), "abc".as_bytes()}
    assert_eq! {strip_color_to_buf("abc\x1b[32m".as_bytes()), "abc".as_bytes()}
    assert_eq! {strip_color_to_buf("\x1b[32mabc".as_bytes()), "abc".as_bytes()}

    assert_eq! {strip_color_to_buf("\x1b[0m.\x1b[32mabc".as_bytes()), ".abc".as_bytes()}
    assert_eq! {strip_color_to_buf("\x1b[0m.\x1b[0m.\x1b[0m\x1b[0m\x1b[32mabc".as_bytes()), "..abc".as_bytes()}
}
