use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use crate::*;
use dbs_device::{DeviceIoMut, PioAddress};

pub const PIT_BASE_PORT: u16 = 0x40;
pub const PIT_PORT_SIZE: u16 = 0x04;
pub const PIT_FREQ_HZ: u64 = 1_193_182;

pub const PIT_GSI: u8 = 2;

struct PitChannel {
    mode: u8,
    rw_mode: u8, // 1=LSB, 2=MSB, 3=LSB+MSB
    initial_count: u16,
    write_lsb: bool,
    enabled: bool,
    start_time: Option<std::time::Instant>,
}

impl PitChannel {
    fn new() -> Self {
        PitChannel {
            mode: 2,    // Rate generator
            rw_mode: 3, // LSB+MSB
            initial_count: 0,
            write_lsb: true,
            enabled: false,
            start_time: None,
        }
    }
    fn period_ns(&self) -> u64 {
        if self.initial_count == 0 {
            65536u64 * 1_000_000_000 / PIT_FREQ_HZ
        } else {
            self.initial_count as u64 * 1_000_000_000 / PIT_FREQ_HZ
        }
    }
    fn next_irq_duration(&self) -> Option<Duration> {
        if !self.enabled {
            return None;
        }
        let period = self.period_ns();
        if let Some(start) = self.start_time {
            let elapsed = start.elapsed().as_nanos() as u64;
            let next = period - (elapsed % period);
            Some(Duration::from_nanos(next))
        } else {
            Some(Duration::from_nanos(period))
        }
    }
}

pub struct PitDevice {
    channels: [PitChannel; 3],
    intr_group: Arc<Box<dyn InterruptSourceGroup>>,
}

impl PitDevice {
    pub fn new(irq_manager: Arc<Box<dyn InterruptManager>>) -> Result<Self> {
        let intr_group =
            irq_manager.create_group(InterruptSourceType::LegacyIrq, PIT_GSI as u32, 1)?;
        Ok(PitDevice {
            channels: [PitChannel::new(), PitChannel::new(), PitChannel::new()],
            intr_group,
        })
    }

    pub fn inject_interrupt(&self) -> Result<()> {
        self.intr_group.trigger(0)
    }

    fn control_write(&mut self, val: u8) {
        println!("control write val: {}", val);
        let ch_idx = ((val >> 6) & 0x03) as usize;
        if ch_idx == 3 {
            return;
        } // readback
        let rw_bits = (val >> 4) & 0x03;
        let mode_bits = (val >> 1) & 0x07;
        let ch = &mut self.channels[ch_idx];
        ch.rw_mode = rw_bits;
        ch.mode = mode_bits & 0x07;
        ch.write_lsb = true;
        ch.enabled = false;
        ch.start_time = None;
    }
    fn channel_write(&mut self, ch_idx: usize, val: u8) {
        println!("channel write channel index: {}, val: {}", ch_idx, val);
        let ch = &mut self.channels[ch_idx];
        match ch.rw_mode {
            1 => {
                // LSB only
                ch.initial_count = (ch.initial_count & 0xFF00) | val as u16;
                ch.enabled = true;
                ch.start_time = Some(std::time::Instant::now());
            }
            2 => {
                // MSB only
                ch.initial_count = (ch.initial_count & 0x00FF) | ((val as u16) << 8);
                ch.enabled = true;
                ch.start_time = Some(std::time::Instant::now());
            }
            3 => {
                // LSB+MSB
                if ch.write_lsb {
                    ch.initial_count = (ch.initial_count & 0xFF00) | val as u16;
                    ch.write_lsb = false;
                } else {
                    ch.initial_count = (ch.initial_count & 0x00FF) | ((val as u16) << 8);
                    ch.write_lsb = true;
                    ch.enabled = true;
                    ch.start_time = Some(std::time::Instant::now());
                }
            }
            _ => {}
        }
    }
}

impl DeviceIoMut for PitDevice {
    fn pio_write(&mut self, _base: PioAddress, offset: PioAddress, data: &[u8]) {
        println!("PIT port offset: {}", offset.raw_value());
        if data.len() != 1 {
            return;
        }
        let val = data[0];
        match offset.raw_value() {
            0 => self.channel_write(0, val),
            1 => self.channel_write(1, val),
            2 => self.channel_write(2, val),
            3 => self.control_write(val),
            _ => {}
        }
    }
    fn pio_read(&mut self, _base: PioAddress, offset: PioAddress, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }
        println!("PIT read offset: {}", offset.raw_value());
        data[0] = match offset.raw_value() {
            0..=2 => self.channels[offset.raw_value() as usize].initial_count as u8,
            _ => 0,
        };
    }
}

pub fn start_pit_timer(pit_device: Arc<Mutex<PitDevice>>) {
    thread::Builder::new()
        .name("pit-timer".to_string())
        .spawn(move || loop {
            let next = {
                let pit = pit_device.lock().unwrap();
                pit.channels[0].next_irq_duration()
            };
            match next {
                Some(duration) => {
                    thread::sleep(duration);

                    let pit = pit_device.lock().unwrap();
                    let _ = pit.inject_interrupt();
                }
                None => {
                    thread::sleep(Duration::from_micros(100));
                }
            }
        })
        .expect("failed to spawn pit-timer thread");
}
