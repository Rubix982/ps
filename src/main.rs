use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use signal_hook::{self, SIGINT};

fn main() {
    println!("Hello, world!");
}
