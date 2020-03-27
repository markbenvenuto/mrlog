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

extern crate json;
extern crate regex;

extern crate crossbeam_channel;

use colored::Colorize;

use regex::*;

use std::borrow::Cow;

use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::vec::Vec;

use structopt::StructOpt;

use anyhow::{Context, Result};

mod shared_stream;
use shared_stream::SharedStreamFactory;

struct LogFormatter {
    re: Regex,
    re_color: Regex,
    use_color: bool,
    log_id: bool,
}

static LOG_FORMAT_PREFIX: &'static str = r#"{"t":{"$date"#;

static LOG_ERROR_REGEX: &'static str = r#"invariant|fassert|failed to load|uncaught exception"#;

static LOG_ATTR_REGEX: &'static str = r#"\{([\w]+)\}"#;

// from duration.h
const LOG_TIME_SUFFIXES_TUPLE: &'static [(&'static str, &'static str)] = &[
    ("Nanos", "ns"),
    ("Micros", "μs"), // GREEK SMALL LETTER MU, 0x03BC or 956 code point
    ("Millis", "ms"),
    ("Seconds", "s"),
    ("Minutes", "min"),
    ("Hours", "hr"),
    ("Days", "d"),
];

fn get_json_str<'a>(v: &'a json::JsonValue, name: &str, line: &str) -> Result<&'a str> {
    let r = v[name]
        .as_str()
        .with_context(|| format!("Failed to find '{}' in JSON log line: {}", name, line))?;
    Ok(r)
}

impl LogFormatter {
    fn new(use_color: bool, log_id: bool) -> LogFormatter {
        LogFormatter {
            re: Regex::new(LOG_ATTR_REGEX).unwrap(),
            re_color: Regex::new(LOG_ERROR_REGEX).unwrap(),
            use_color: use_color,
            log_id: log_id,
        }
    }

    #[cfg(test)]
    fn new_for_test() -> LogFormatter {
        LogFormatter {
            re: Regex::new(LOG_ATTR_REGEX).unwrap(),
            re_color: Regex::new(LOG_ERROR_REGEX).unwrap(),
            use_color: false,
            log_id: false,
        }
    }

    fn format_line<'a>(
        &self,
        date: &str,
        log_level: &str,
        component: &str,
        context: &str,
        id: u64,
        msg: Cow<'a, str>,
    ) -> String {
        if self.log_id {
            return format!(
                "{} {:<2} {:<8} {:<5} [{}] {}",
                date, log_level, component, id, context, msg
            );
        }
        format!(
            "{} {:<2} {:<8} [{}] {}",
            date, log_level, component, context, msg
        )
    }

    fn maybe_color_text<'a>(&self, s: &'a str) -> Cow<'a, str> {
        if !self.use_color {
            return Cow::from(s);
        }

        if self.re_color.is_match(s) {
            return Cow::Owned(s.red().to_string());
        }

        return Cow::from(s);
    }

    fn log_to_str(&self, s: &str) -> Result<String> {
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

        if msg.contains("{") {
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
                    })?),
                ));
            }

            let msg_fmt = self.re.replace_all(msg, |caps: &Captures| {
                // println!("{}", &caps[1]);
                let v = &attr[&caps[1]];
                if v.is_object() {
                    return v.dump();
                }
                if v.is_number() {
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
                            return v.dump() + &short;
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
                self.maybe_color_text(&msg_fmt),
            ))
        } else {
            if !attr.is_empty() {
                let s = String::from(msg) + attr.dump().as_ref();
                return Ok(self.format_line(
                    d,
                    log_level,
                    component,
                    context,
                    log_id,
                    self.maybe_color_text(&s),
                ));
            }

            Ok(self.format_line(
                d,
                log_level,
                component,
                context,
                log_id,
                self.maybe_color_text(msg),
            ))
        }
    }

    fn fuzzy_log_to_str(&self, s: &str) -> Result<String> {
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

fn convert_lines<T>(lf: LogFormatter, lines: T, writer: &mut dyn io::Write)
where
    T: Iterator<Item = io::Result<String>>,
{
    let lf_byte = vec![10];

    for line in lines {
        if let Ok(line_opt) = line {
            let convert_result = lf.fuzzy_log_to_str(&line_opt.as_str());
            match convert_result {
                Ok(s) => {
                    writer.write(s.as_bytes()).unwrap();
                }
                Err(m) => {
                    // TODO - format error message better
                    writer.write(m.to_string().as_bytes()).unwrap();
                }
            }
            writer.write(lf_byte.as_ref()).unwrap();
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
}

fn get_writer<'a>(
    file_name_buf: Option<PathBuf>,
    stdout: &'a io::Stdout,
) -> Result<Box<dyn io::Write + 'a>> {

    match file_name_buf {
        Some(file_name) => {
            Ok(Box::new(File::create(file_name).with_context(|| {
                format!("Failed to open file 'xxx' for output")
            })?))
        }

        None => {
            let out_lock = stdout.lock();
            Ok(Box::new(out_lock))
        }
    }
}

fn main() -> Result<()> {
    let args = Cli::from_args();

    let stdout_handle = io::stdout();
    let mut writer = get_writer(args.output, &stdout_handle)?;

    let lf = LogFormatter::new(args.color, args.id);

    if args.execute & args.path_or_cmd.is_some() {
        let mut builder = Command::new(&args.path_or_cmd.unwrap());
        for arg in args.cmd_args {
            builder.arg(arg);
        }

        let child = builder
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        let ssf = SharedStreamFactory::new();
        let mut stdout_writer = ssf.get_writer();

        let mut stderr_writer = ssf.get_writer();

        let mut output_out = child
            .stdout
            .ok_or_else(|| "Failed to open child pipe's stdout")
            .unwrap();
        let mut output_err = child
            .stderr
            .ok_or_else(|| "Failed to open child pipe's stderr")
            .unwrap();

        let ts = thread::spawn(move || {
            let mut v = Vec::new();
            v.resize(8192, 0);
            loop {
                let ret = output_out.read(v.as_mut_slice());
                match ret {
                    Ok(size) => {
                        if size == 0 {
                            break;
                        }
                        stdout_writer.write(&v.as_slice()[0..size]).unwrap();
                    }
                    Err(e) => {
                        eprintln!("Unexpected error reading from standard out {:?}", e);
                        break;
                    }
                };
            }
        });

        let ts2 = thread::spawn(move || {
            let mut v = Vec::new();
            v.resize(8192, 0);
            loop {
                let ret = output_err.read(v.as_mut_slice());
                match ret {
                    Ok(size) => {
                        if size == 0 {
                            break;
                        }
                        stderr_writer.write(&v.as_slice()[0..size]).unwrap();
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
        convert_lines(lf, lines, &mut writer);

        ts.join().unwrap();
        ts2.join().unwrap();
    } else {
        match args.path_or_cmd {
            Some(file_name) => {
                let p = std::path::PathBuf::from(file_name);
                let lines = read_lines(p)?;

                convert_lines(lf, lines, &mut writer);
            }
            None => {
                let stdin = io::stdin();
                let handle_in = stdin.lock();

                let lines = io::BufReader::new(handle_in).lines();
                convert_lines(lf, lines, &mut writer);
            }
        }
    }

    Ok(())
}

#[test]
fn test_log_to_str() {
    let lf = LogFormatter::new_for_test();

    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":20533,"ctx":"initandlisten","msg":"DEBUG build (which is slower)"}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] DEBUG build (which is slower)"};
}

#[test]
fn test_log_to_str_with_replacements() {
    let lf = LogFormatter::new_for_test();
    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"{openSSLVersion_OpenSSL_version}","attr":{"openSSLVersion_OpenSSL_version":"OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"}}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"};

    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"test {test1}","attr":{"test1":123}}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] test 123"};

    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"test {test1}","attr":{"test1":{"abc":123}}}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] test {\"abc\":123}"};
}

#[test]
fn test_log_to_str_with_duration_replacements() {
    let lf = LogFormatter::new_for_test();
    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"test {duration}","attr":{"durationMillis":123}}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] test 123ms"};

    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"test {duration}","attr":{"durationMicros":123}}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] test 123μs"};
}

#[test]
fn test_fuzzy_log() {
    let lf = LogFormatter::new_for_test();
    assert_eq! { lf.fuzzy_log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"{openSSLVersion_OpenSSL_version}","attr":{"openSSLVersion_OpenSSL_version":"OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"}}"#).unwrap(), "2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"};

    assert_eq! { lf.fuzzy_log_to_str(r#"[js_test:txn_two_phase_commit_basic] 2020-02-15T23:32:14.540-0500 d20021| {"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL","id":23400,"ctx":"initandlisten","msg":"{openSSLVersion_OpenSSL_version}","attr":{"openSSLVersion_OpenSSL_version":"OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"}}"#).unwrap(), "[js_test:txn_two_phase_commit_basic] 2020-02-15T23:32:14.540-0500 d20021| 2020-02-15T23:32:14.539-0500 I  CONTROL  [initandlisten] OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"};
}
