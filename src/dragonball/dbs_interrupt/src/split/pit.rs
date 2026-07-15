use crate::*;
use dbs_device::{DeviceIoMut, PioAddress};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
pub const PIT_BASE_PORT: u16 = 0x40;
pub const PIT_PORT_SIZE: u16 = 0x04;
pub const PIT_FREQ_HZ: u64 = 1_193_182;
pub const PIT_GSI: u8 = 2;

struct PitChannel {
    mode: u8,
    rw_mode: u8,
    initial_count: u16,
    write_lsb: bool,
    read_lsb: bool,
    enabled: bool,
    start_time: Option<Instant>,
    latched: bool,
    latch_value: u16,
}

impl PitChannel {
    fn new() -> Self {
        PitChannel {
            mode: 2,
            rw_mode: 3,
            initial_count: 0,
            write_lsb: true,
            read_lsb: true,
            enabled: false,
            start_time: None,
            latched: false,
            latch_value: 0,
        }
    }
    fn effective_count(&self) -> u64 {
        if self.initial_count == 0 {
            65536
        } else {
            self.initial_count as u64
        }
    }
    fn period_ns(&self) -> u64 {
        self.effective_count() * 1_000_000_000 / PIT_FREQ_HZ
    }

    fn current_count(&self) -> u16 {
        let count = self.effective_count();
        if let Some(start) = self.start_time {
            let elapsed_ns = start.elapsed().as_nanos() as u64;
            let period = self.period_ns();
            let phase_ns = elapsed_ns % period;
            let remaining = period - phase_ns;
            (remaining * count / period) as u16
        } else {
            self.initial_count
        }
    }

    fn read_count(&mut self) -> u8 {
        let count = if self.latched {
            self.latch_value
        } else {
            self.current_count()
        };
        match self.rw_mode {
            1 => {
                // LSB only
                count as u8
            }
            2 => {
                // MSB only
                (count >> 8) as u8
            }
            3 => {
                if self.read_lsb {
                    self.read_lsb = false;
                    count as u8
                } else {
                    self.read_lsb = true;
                    if self.latched {
                        self.latched = false;
                    }
                    (count >> 8) as u8
                }
            }
            _ => 0,
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
        let ch_idx = ((val >> 6) & 0x03) as usize;
        let rw_bits = (val >> 4) & 0x03;
        let mode_bits = (val >> 1) & 0x07;
        if ch_idx == 3 {
            return; // read-back
        }

        // Counter Latch Command
        if rw_bits == 0 {
            let ch = &mut self.channels[ch_idx];
            ch.latch_value = ch.current_count();
            ch.latched = true;
            ch.read_lsb = true;
            return;
        }
        let ch = &mut self.channels[ch_idx];
        ch.rw_mode = rw_bits;
        ch.mode = mode_bits & 0x07;
        ch.write_lsb = true;
        ch.read_lsb = true;
        ch.latched = false;
    }

    fn channel_write(&mut self, ch_idx: usize, val: u8) {
        let ch = &mut self.channels[ch_idx];
        match ch.rw_mode {
            1 => {
                ch.initial_count = (ch.initial_count & 0xFF00) | val as u16;
                ch.enabled = true;
                ch.start_time = Some(Instant::now());
                ch.read_lsb = true;
            }
            2 => {
                ch.initial_count = (ch.initial_count & 0x00FF) | ((val as u16) << 8);
                ch.enabled = true;
                ch.start_time = Some(Instant::now());
                ch.read_lsb = true;
            }
            3 => {
                if ch.write_lsb {
                    ch.initial_count = (ch.initial_count & 0xFF00) | val as u16;
                    ch.write_lsb = false;
                } else {
                    ch.initial_count = (ch.initial_count & 0x00FF) | ((val as u16) << 8);
                    ch.write_lsb = true;
                    ch.enabled = true;
                    ch.start_time = Some(Instant::now());
                    ch.read_lsb = true;
                }
            }
            _ => {}
        }
    }
}

impl DeviceIoMut for PitDevice {
    fn pio_write(&mut self, _base: PioAddress, offset: PioAddress, data: &[u8]) {
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
        data[0] = match offset.raw_value() {
            0..=2 => {
                let idx = offset.raw_value() as usize;
                self.channels[idx].read_count()
            }
            _ => 0,
        };
    }
}

pub fn start_pit_timer(pit_device: Arc<Mutex<PitDevice>>) -> Result<()> {
    let configs = [InterruptSourceConfig::LegacyIrq(LegacyIrqSourceConfig {})];
    pit_device.lock().unwrap().intr_group.enable(&configs)?;
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
    Ok(())
}
