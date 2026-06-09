use evdev::{uinput::VirtualDeviceBuilder, AttributeSet, Key, InputEvent};
use tokio::sync::mpsc;

pub struct InputCommand {
    pub button_code: u16,
    pub is_pressed: bool,
}

pub fn start_input_handler(mut rx: mpsc::Receiver<InputCommand>) {
    // Kita gunakan spawn_blocking karena evdev membuat blocking syscall ke /dev/uinput
    tokio::task::spawn_blocking(move || {
        let mut keys = AttributeSet::<Key>::new();
        // Setup tombol/sinyal dasar virtual device yang diizinkan untuk diregister.
        // Anda bisa menambahkan Key lain sesuai kebutuhan (contoh: D-PAD, dsb)
        keys.insert(Key::BTN_SOUTH); // Controller A
        keys.insert(Key::BTN_EAST);  // Controller B
        keys.insert(Key::BTN_NORTH); // Controller X
        keys.insert(Key::BTN_WEST);  // Controller Y
        keys.insert(Key::BTN_TL);    // L1
        keys.insert(Key::BTN_TR);    // R1
        
        let device_result = VirtualDeviceBuilder::new()
            .unwrap()
            .name("ZRTP Input Interface")
            .with_keys(&keys)
            .unwrap()
            .build();
            
        let mut device = match device_result {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[INPUT] Gagal membuat virtual device uinput: {}. PERHATIAN: Pastikan Anda menjalankan program ini dengan `sudo` agar memiliki akses ke /dev/uinput.", e);
                return;
            }
        };

        println!("[INPUT] ZRTP Input Interface aktif dan terhubung ke Kernel Linux.");

        // Loop untuk menerima command dari network layer (TCP)
        while let Some(cmd) = rx.blocking_recv() {
            let key = Key::new(cmd.button_code);
            let value = if cmd.is_pressed { 1 } else { 0 };
            let event = InputEvent::new(evdev::EventType::KEY, key.code(), value);
            
            // Emit event penekanan/pelepasan tombol
            if let Err(e) = device.emit(&[event]) {
                eprintln!("[INPUT] Gagal mengirim event uinput: {}", e);
            } else {
                println!("[INPUT] Event Terkirim - Key: {:?}, Pressed: {}", key, cmd.is_pressed);
            }
        }
    });
}
