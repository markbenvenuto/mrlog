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

use regex::*;

use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::Path;

use structopt::StructOpt;

struct LogFormatter {
    re: Regex,
}

static LOG_FORMAT_PREFIX : &'static str = r#"{"t":{"$date"#;

 impl LogFormatter {
    fn new() -> LogFormatter {
        LogFormatter {
            re: Regex::new(r#"\{([\w]+)\}"#).unwrap(),
        }
    }

    fn log_to_str(&self, s: &str) -> String {
        let parsed = json::parse(s).unwrap();

        let d = parsed["t"]["$date"].as_str().unwrap();
        let log_level = parsed["s"].as_str().unwrap();
        let component = parsed["c"].as_str().unwrap();
        let context = parsed["ctx"].as_str().unwrap();
        let msg = parsed["msg"].as_str().unwrap();

        if msg.contains("{") {
            // Handle messages which are just an empty {}
            if msg == "{}" {
                return format!(
                    "{} {} {:<8} [{}] {}",
                    d, log_level, component, context, parsed["attr"]["message"].as_str().unwrap()
                )
            }

            let msg_fmt = self.re.replace_all(msg, |caps: &Captures| {
                // println!("{}", &caps[1]);
                String::from(parsed["attr"][&caps[1]].as_str().unwrap())
            });

            format!(
                "{} {} {:<8} [{}] {}",
                d, log_level, component, context, msg_fmt
            )
        } else {
            format!("{} {} {:<8} [{}] {}", d, log_level, component, context, msg)
        }
    }

    fn fuzzy_log_to_str(&self, s: &str) -> String {
        if s.starts_with(LOG_FORMAT_PREFIX) {
            return self.log_to_str(s);
        }

        // TODO - become stateful and rember where we found a previous start
        let f = s.find(LOG_FORMAT_PREFIX);
        if f.is_some() {
            let end = self.log_to_str(s[f.unwrap() .. s.len()].as_ref());
            return String::from(&s[0..f.unwrap()]) + end.as_ref();
        }

        // We do not think it is a JSON log line, return it as is
        String::from(s)
    }

}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

#[derive(StructOpt)]
/// Convertes MongoDB 4.4 JSON log format to text format. Writes converted file to stdout
struct Cli {
    /// Optional path to the file to read, defaults to stdin
    #[structopt(parse(from_os_str))]
    path: Option<std::path::PathBuf>,
}

fn main() {
    let args = Cli::from_args();

    let lf = LogFormatter::new();

    if args.path.is_none() {
        let stdin = io::stdin();
        let handle_in = stdin.lock();

        let stdout = io::stdout();
        let mut handle_out = stdout.lock();

        let lines = io::BufReader::new(handle_in).lines();

        let lf_byte = vec!{10};
        for line in lines {
    
            if let Ok(line_opt) = line {
                handle_out.write(lf.fuzzy_log_to_str(&line_opt.as_str()).as_bytes()).unwrap();
                handle_out.write(lf_byte.as_ref()).unwrap();
            }
        }
    
    }  else {
        let stdout = io::stdout();
        let mut handle_out = stdout.lock();

        let lines = read_lines(args.path.unwrap()).unwrap();

        let lf_byte = vec!{10};
        for line in lines {
    
            if let Ok(line_opt) = line {
                handle_out.write(lf.fuzzy_log_to_str(&line_opt.as_str()).as_bytes()).unwrap();
                handle_out.write(lf_byte.as_ref()).unwrap();
            }
        }
    }
}

#[test]
fn test_log_to_str() {
    let lf = LogFormatter::new();

    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":20533,"ctx":"initandlisten","msg":"DEBUG build (which is slower)"}"#), "2020-02-15T23:32:14.539-0500 I CONTROL  [initandlisten] DEBUG build (which is slower)"};
}

#[test]
fn test_log_to_str_with_replacements() {
    let lf = LogFormatter::new();
    assert_eq! { lf.log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"{openSSLVersion_OpenSSL_version}","attr":{"openSSLVersion_OpenSSL_version":"OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"}}"#), "2020-02-15T23:32:14.539-0500 I CONTROL  [initandlisten] OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"};
}

#[test]
fn test_fuzzy_log() {
    let lf = LogFormatter::new();
    assert_eq! { lf.fuzzy_log_to_str(r#"{"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL", "id":23400,"ctx":"initandlisten","msg":"{openSSLVersion_OpenSSL_version}","attr":{"openSSLVersion_OpenSSL_version":"OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"}}"#), "2020-02-15T23:32:14.539-0500 I CONTROL  [initandlisten] OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"};

    assert_eq! { lf.fuzzy_log_to_str(r#"[js_test:txn_two_phase_commit_basic] 2020-02-15T23:32:14.540-0500 d20021| {"t":{"$date":"2020-02-15T23:32:14.539-0500"},"s":"I", "c":"CONTROL","id":23400,"ctx":"initandlisten","msg":"{openSSLVersion_OpenSSL_version}","attr":{"openSSLVersion_OpenSSL_version":"OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"}}"#), "[js_test:txn_two_phase_commit_basic] 2020-02-15T23:32:14.540-0500 d20021| 2020-02-15T23:32:14.539-0500 I CONTROL  [initandlisten] OpenSSL version: OpenSSL 1.1.1d FIPS  10 Sep 2019"};
}