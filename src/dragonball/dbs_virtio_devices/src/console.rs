use crate::{
    ActivateResult, ConfigResult, DbsGuestAddressSpace, VirtioDevice,
    VirtioDeviceConfig, VirtioDeviceInfo, VirtioQueueConfig, TYPE_VIRTIO_CONSOLE,
};

use dbs_device::resources::ResourceConstraint;
use dbs_utils::epoll_manager::{EpollManager, EventOps, EventSet, Events, MutEventSubscriber, SubscriberId};

use std::any::Any;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use log::{error, trace};
use thiserror::Error;
use virtio_bindings::bindings::virtio_blk::{VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1};
use virtio_queue::{Error as VqError, QueueOwnedT, QueueSync, QueueT};
use vm_memory::{
    ByteValued, Bytes, GuestAddressSpace, GuestMemoryError, GuestMemoryRegion, GuestRegionMmap,
};

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

// New descriptors are pending on input queue
const INPUT_QUEUE_EVENT: u32 = 0;
// New descriptors are pending on output queue
const OUTPUT_QUEUE_EVENT: u32 = 1;
// Input file written to
const FILE_EVENT: u32 = 2;

const CONSOLE_DRIVER_NAME: &str = "virtio-console";

const VIRTIO_CONSOLE_F_SIZE: u64 = 0;

const CONFIG_SPACE_SIZE: usize = 12;

#[derive(Error, Debug)]
pub enum ConsoleError {
    /// Virtio Queue related error.
    #[error("Virtio Queue error: {0}")]
    VirtioQueueError(#[source] VqError),
    /// Guest gave us too few descriptors in a descriptor chain.
    #[error("not enough descriptors for request.")]
    DescriptorChainTooShort,
    /// Failed to write to guest memory.
    #[error("Failed to write to guest memory: {0}")]
    GuestMemoryWrite(#[source] GuestMemoryError),
    /// Failed to write to guest memory.
    #[error("Failed to read from guest memory: {0}")]
    GuestMemoryRead(#[source] GuestMemoryError),
    /// Failed to write output
    #[error("Failed to write output: {0}")]
    OutputWrite(#[source] std::io::Error),
    /// Failed to flush output
    #[error("Failed to flush output: {0}")]
    OutputFlush(#[source] std::io::Error),
}

#[derive(Copy, Clone)]
pub struct VirtioConsoleConfig {
    cols: u16,
    rows: u16,
    max_nr_ports: u32,
    emerg_wr: u32,
}

impl Default for VirtioConsoleConfig {
    fn default() -> Self {
        VirtioConsoleConfig {
            cols: 0,
            rows: 0,
            max_nr_ports: 1,
            emerg_wr: 0,
        }
    }
}

unsafe impl ByteValued for VirtioConsoleConfig {}

pub(crate) struct VirtioConsoleEpollHandler<
    AS: GuestAddressSpace,
    Q: QueueT + Send = QueueSync,
    R: GuestMemoryRegion = GuestRegionMmap,
> {
    pub(crate) config: VirtioDeviceConfig<AS, Q, R>,
    pub(crate) input_queue: VirtioQueueConfig<Q>,
    pub(crate) output_queue: VirtioQueueConfig<Q>,
    in_buffer: Arc<Mutex<VecDeque<u8>>>,
    endpoint: Endpoint,
    out: Option<Box<dyn Write + Send>>,
}

#[derive(Clone)]
pub enum Endpoint {
    File(Arc<File>),
    FilePair(Arc<File>, Arc<File>),
    Null,
}

impl Endpoint {
    fn out_file(&self) -> Option<&File> {
        match self {
            Self::File(f) => Some(f),
            Self::FilePair(f, _) => Some(f),
            Self::Null => None,
        }
    }

    fn in_file(&self) -> Option<&File> {
        match self {
            Self::File(_) => None,
            Self::FilePair(_, f) => Some(f),
            Self::Null => None,
        }
    }
}

impl<AS: DbsGuestAddressSpace, Q: QueueT + Send, R: GuestMemoryRegion>
    VirtioConsoleEpollHandler<AS, Q, R>
{
    fn new(
        mut config: VirtioDeviceConfig<AS, Q, R>,
        in_buffer: Arc<Mutex<VecDeque<u8>>>,
        endpoint: Endpoint,
    ) -> Self {
        let out_file = endpoint.out_file();
        let out = if let Some(out_file) = out_file {
            let writer = out_file.try_clone().unwrap();
            Some(Box::new(writer) as Box<dyn Write + Send>)
        } else {
            None
        };

        let input_queue = config.queues.remove(0);
        let output_queue = config.queues.remove(0);

        Self {
            config,
            input_queue,
            output_queue,
            in_buffer,
            endpoint,
            out,
        }
    }

    fn process_input_queue(&mut self) -> Result<bool, ConsoleError> {
        let mut in_buffer = self.in_buffer.lock().unwrap();

        if in_buffer.is_empty() {
            return Ok(false);
        }

        let mem = self.config.lock_guest_memory();
        let mut queue_guard = self.input_queue.queue_mut().lock();
        let mut iter = queue_guard
            .iter(mem.clone())
            .map_err(ConsoleError::VirtioQueueError)?;
        let mut used_desc_info = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;

        for mut desc_chain in &mut iter {
            let desc = desc_chain
                .next()
                .ok_or(ConsoleError::DescriptorChainTooShort)?;
            let len = std::cmp::min(desc.len() as usize, in_buffer.len());
            let source_slice = in_buffer.drain(..len).collect::<Vec<u8>>();

            mem.write_slice(&source_slice[..], desc.addr())
                .map_err(ConsoleError::GuestMemoryWrite)?;

            used_desc_info[used_count] = (desc_chain.head_index(), len as u32);
            used_count += 1;

            if in_buffer.is_empty() {
                break;
            }
        }

        drop(queue_guard);

        for &(desc_index, len) in &used_desc_info[..used_count] {
            self.input_queue.add_used(mem.deref(), desc_index, len);
        }

        Ok(used_count > 0)
    }

    fn process_output_queue(&mut self) -> Result<bool, ConsoleError> {
        let mem = self.config.lock_guest_memory();
        let mut queue_guard = self.output_queue.queue_mut().lock();
        let mut iter = queue_guard
            .iter(mem.clone())
            .map_err(ConsoleError::VirtioQueueError)?;
        let mut used_desc_info = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;

        for mut desc_chain in &mut iter {
            let desc = desc_chain
                .next()
                .ok_or(ConsoleError::DescriptorChainTooShort)?;

            if let Some(out) = &mut self.out {
                let mut buf = Vec::new();
                mem.write_to(desc.addr(), &mut buf, desc.len() as usize)
                    .map_err(ConsoleError::GuestMemoryRead)?;

                out.write_all(&buf).map_err(ConsoleError::OutputWrite)?;
                out.flush().map_err(ConsoleError::OutputFlush)?;
            }

            used_desc_info[used_count] = (desc_chain.head_index(), desc.len());
            used_count += 1;
        }

        drop(queue_guard);

        for &(desc_index, len) in &used_desc_info[..used_count] {
            self.output_queue.add_used(mem.deref(), desc_index, len);
        }

        Ok(used_count > 0)
    }
}

impl<AS: DbsGuestAddressSpace, Q: QueueT + Send, R: GuestMemoryRegion> MutEventSubscriber
    for VirtioConsoleEpollHandler<AS, Q, R>
where
    AS: 'static + GuestAddressSpace + Send + Sync,
{
    fn init(&mut self, ops: &mut EventOps) {
        trace!(
            target: CONSOLE_DRIVER_NAME,
            "{}: VirtioConsoleEpollHandler::init()",
            CONSOLE_DRIVER_NAME,
        );

        let events = Events::with_data(
            self.input_queue.eventfd.as_ref(),
            INPUT_QUEUE_EVENT,
            EventSet::IN,
        );
        if let Err(e) = ops.add(events) {
            error!(
                "{}: failed to register INPUT QUEUE event, {:?}",
                CONSOLE_DRIVER_NAME, e
            );
        }

        let events = Events::with_data(
            self.output_queue.eventfd.as_ref(),
            OUTPUT_QUEUE_EVENT,
            EventSet::IN,
        );
        if let Err(e) = ops.add(events) {
            error!(
                "{}: failed to register OUTPUT QUEUE event, {:?}",
                CONSOLE_DRIVER_NAME, e
            );
        }

        if let Some(in_file) = self.endpoint.in_file() {
            let events = Events::with_data(&in_file.as_raw_fd(), FILE_EVENT, EventSet::IN);
            if let Err(e) = ops.add(events) {
                error!(
                    "{}: failed to register FILE event, {:?}",
                    CONSOLE_DRIVER_NAME, e
                );
            }
        }
    }

    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        let idx = events.data();

        trace!(
            target: CONSOLE_DRIVER_NAME,
            "{}: VirtioConsoleEpollHandler::process() idx {}",
            CONSOLE_DRIVER_NAME,
            idx,
        );

        match idx {
            INPUT_QUEUE_EVENT => match self.process_input_queue() {
                Ok(needs_notification) => {
                    if needs_notification {
                        if let Err(e) = self.input_queue.notify() {
                            error!(
                                "{}: Failed to signal used queue: {:?}",
                                CONSOLE_DRIVER_NAME, e
                            );
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "{}: Failed to handle {} queue: {:?}",
                        CONSOLE_DRIVER_NAME, idx, e
                    );
                }
            },
            OUTPUT_QUEUE_EVENT => match self.process_output_queue() {
                Ok(needs_notification) => {
                    if needs_notification {
                        if let Err(e) = self.output_queue.notify() {
                            error!(
                                "{}: Failed to signal used queue: {:?}",
                                CONSOLE_DRIVER_NAME, e
                            );
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "{}: Failed to handle {} queue: {:?}",
                        CONSOLE_DRIVER_NAME, idx, e
                    );
                }
            },
            FILE_EVENT => {
                let mut input = [0u8; 64];
                if let Some(ref mut in_file) = self.endpoint.in_file() {
                    if let Ok(count) = in_file.read(&mut input) {
                        let mut in_buffer = self.in_buffer.lock().unwrap();
                        in_buffer.extend(&input[..count]);
                    }

                    match self.process_input_queue() {
                        Ok(needs_notification) => {
                            if needs_notification {
                                if let Err(e) = self.input_queue.notify() {
                                    error!(
                                        "{}: Failed to signal used queue: {:?}",
                                        CONSOLE_DRIVER_NAME, e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                "{}: Failed to handle {} queue: {:?}",
                                CONSOLE_DRIVER_NAME, idx, e
                            );
                        }
                    }
                }
            }
            _ => {
                error!("{}: unknown idx {}", CONSOLE_DRIVER_NAME, idx);
            }
        }
    }
}

fn get_win_size(tty: &dyn AsRawFd) -> (u16, u16) {
    #[repr(C)]
    #[derive(Default)]
    struct WindowSize {
        rows: u16,
        cols: u16,
        xpixel: u16,
        ypixel: u16,
    }
    let mut ws: WindowSize = WindowSize::default();

    // SAFETY: FFI call with correct arguments
    unsafe {
        libc::ioctl(tty.as_raw_fd(), libc::TIOCGWINSZ, &mut ws);
    }

    (ws.cols, ws.rows)
}

pub struct Console<AS: GuestAddressSpace> {
    device_info: VirtioDeviceInfo,
    _config: Arc<Mutex<VirtioConsoleConfig>>,
    endpoint: Endpoint,
    in_buffer: Arc<Mutex<VecDeque<u8>>>,
    subscriber_id: Option<SubscriberId>,
    phantom: PhantomData<AS>,
}

impl<AS: GuestAddressSpace> Console<AS> {
    pub fn new(
        epoll_manager: EpollManager,
        endpoint: Endpoint,
        f_iommu_platform: bool,
    ) -> Result<Self, ConsoleError> {
        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_CONSOLE_F_SIZE);
        if f_iommu_platform {
            avail_features |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
        }

        let mut config = VirtioConsoleConfig::default();
        if let Some(tty) = endpoint.out_file().as_ref().map(|t| t.try_clone().unwrap()) {
            let (cols, rows) = get_win_size(&tty);
            config.cols = cols;
            config.rows = rows;
        }
        

        let config_space = Self::build_config_space(config);

        Ok(Console {
            device_info: VirtioDeviceInfo::new(
                CONSOLE_DRIVER_NAME.to_string(),
                avail_features,
                Arc::new(QUEUE_SIZES.to_vec()),
                config_space,
                epoll_manager,
            ),
            _config: Arc::new(Mutex::new(config)),
            endpoint,
            in_buffer: Arc::new(Mutex::new(VecDeque::new())),
            subscriber_id: None,
            phantom: PhantomData,
        })
    }

    fn build_config_space(console_config: VirtioConsoleConfig) -> Vec<u8> {
        let mut config = Vec::with_capacity(CONFIG_SPACE_SIZE);
        for i in 0..2 {
            config.push((console_config.cols >> (8 * i)) as u8);
        }
        for i in 0..2 {
            config.push((console_config.rows >> (8 * i)) as u8);
        }
        for i in 0..4 {
            config.push((console_config.max_nr_ports >> (8 * i)) as u8);
        }
        for i in 0..4 {
            config.push((console_config.emerg_wr >> (8 * i)) as u8);
        }

        config
    }
}

impl<AS, Q, R> VirtioDevice<AS, Q, R> for Console<AS>
where
    AS: DbsGuestAddressSpace,
    Q: QueueT + Send + 'static,
    R: GuestMemoryRegion + Send + Sync + 'static,
{
    fn device_type(&self) -> u32 {
        TYPE_VIRTIO_CONSOLE
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.device_info.queue_sizes
    }

    fn get_avail_features(&self, page: u32) -> u32 {
        self.device_info.get_avail_features(page)
    }

    fn set_acked_features(&mut self, page: u32, value: u32) {
        trace!(
            target: CONSOLE_DRIVER_NAME,
            "{}: VirtioDevice::set_acked_features({}, 0x{:x})",
            CONSOLE_DRIVER_NAME,
            page,
            value
        );
        self.device_info.set_acked_features(page, value);
    }

    fn read_config(&mut self, offset: u64, data: &mut [u8]) -> ConfigResult {
        trace!(
            target: CONSOLE_DRIVER_NAME,
            "{}: VirtioDevice::read_config(0x{:x}, {:?})",
            CONSOLE_DRIVER_NAME,
            offset,
            data
        );

        self.device_info.read_config(offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> ConfigResult {
        trace!(
            target: CONSOLE_DRIVER_NAME,
            "{}: VirtioDevice::write_config(0x{:x}, {:?})",
            CONSOLE_DRIVER_NAME,
            offset,
            data
        );
        self.device_info.write_config(offset, data)
    }

    fn activate(&mut self, config: VirtioDeviceConfig<AS, Q, R>) -> ActivateResult {
        trace!(
            target: CONSOLE_DRIVER_NAME,
            "{}: VirtioDevice::activate()",
            CONSOLE_DRIVER_NAME,
        );


        self.device_info.check_queue_sizes(&config.queues)?;
        trace!(
            "{}: activate acked_features 0x{:x}",
            CONSOLE_DRIVER_NAME,
            self.device_info.acked_features
        );

        let handler = Box::new(VirtioConsoleEpollHandler::new(
            config,
            self.in_buffer.clone(),
            self.endpoint.clone(),
        ));

        self.subscriber_id = Some(self.device_info.register_event_handler(handler));

        Ok(())
    }

    fn get_resource_requirements(
        &self,
        requests: &mut Vec<ResourceConstraint>,
        use_generic_irq: bool,
    ) {
        trace!(
            target: CONSOLE_DRIVER_NAME,
            "{}: VirtioDevice::get_resource_requirements()",
            CONSOLE_DRIVER_NAME,
        );

        requests.push(ResourceConstraint::LegacyIrq { irq: None });
        if use_generic_irq {
            // Allocate one irq for device configuration change events, and one irq for each queue.
            requests.push(ResourceConstraint::GenericIrq {
                size: (self.device_info.queue_sizes.len() + 1) as u32,
            });
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
