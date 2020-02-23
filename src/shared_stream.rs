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

use crossbeam_channel::unbounded;
use std::sync::Mutex;
use std::vec::Vec;
use std::io;

type ByteSender = crossbeam_channel::Sender<std::vec::Vec<u8>>;
type ByteReceiver = crossbeam_channel::Receiver<std::vec::Vec<u8>>;

pub struct SharedStreamFactory {
    sender: ByteSender,
    receiver: ByteReceiver,
    readers: Mutex<usize>,
    writers: Mutex<usize>,
}

pub struct SharedStreamReader {
    receiver: ByteReceiver,
    buffer: Vec<u8>,
    writers: usize,
}

pub struct SharedStreamWriter {
    sender: ByteSender,
}

impl SharedStreamFactory {
    pub fn new() -> SharedStreamFactory {
        let (send, recv) = unbounded::<std::vec::Vec<u8>>();

        SharedStreamFactory {
            sender: send,
            receiver: recv,
            readers: Mutex::new(0),
            writers: Mutex::new(0),
        }
    }

    pub fn get_reader(self) -> SharedStreamReader {
        let mut lck = self.readers.lock().expect("Lock should not fail");
        if *lck == 1 {
            unimplemented!("Only one reader is suported");
        }

        *lck += 1;
        let ssr = SharedStreamReader {
            writers: *(self.writers.lock().unwrap()),
            receiver: self.receiver.clone(),
            buffer: Vec::<u8>::new(),
        };

        drop(self.receiver);
        drop(self.sender);

        ssr
    }

    pub fn get_writer(&self) -> SharedStreamWriter {
        let mut lk = self.writers.lock().unwrap();
        *lk += 1;

        SharedStreamWriter {
            sender: self.sender.clone(),
        }
    }
}

impl io::Read for SharedStreamReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Return buffered data first before calling into channel
        if self.buffer.len() > 0 {
            let min_len = std::cmp::min(buf.len(), self.buffer.len());
            buf[0..min_len].copy_from_slice(&self.buffer[0..min_len]);
            if self.buffer.len() > min_len {
                self.buffer.drain(0..min_len);
            } else {
                self.buffer.clear();
            }

            return Ok(min_len);
        }

        loop {
            // If we have no writers left, return EOF (i.e. zero length)
            if self.writers == 0 {
                return Ok(0);
            }

            let ret = self.receiver.recv();
            match ret {
                Ok(v) => {
                    if v.len() == 0 {
                        self.writers -= 1;

                        if self.writers > 0 {
                            return Ok(0);
                        }
                        continue;
                    }

                    // Buffer the extra data if needed
                    let mut len = buf.len();
                    if v.len() > buf.len() {
                        buf.copy_from_slice(&v.as_slice()[0..buf.len()]);
                        self.buffer.resize(v.len() - buf.len(), 0);
                        self.buffer.copy_from_slice(&v.as_slice()[buf.len()..]);
                    } else {
                        buf[0..v.len()].copy_from_slice(v.as_slice());
                        len = v.len();
                    }
                    return Ok(len);
                }
                Err(e) => return Err(io::Error::new(io::ErrorKind::NotConnected, e)),
            }
        }
    }
}

impl io::Write for SharedStreamWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let v = Vec::from(buf);
        let ret = self.sender.send(v);
        match ret {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(io::Error::new(io::ErrorKind::NotConnected, e)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl std::ops::Drop for SharedStreamWriter {
    fn drop(&mut self) {
        // Send any empty buffer to signal the reader that we are done
        let v = Vec::new();
        self.sender.send(v).expect("Huh");
    }
}
