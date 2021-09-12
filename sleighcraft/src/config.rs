#[derive(Copy, Clone)]
#[repr(i32)]
pub enum Mode {
    // Default Address size is 16-bit
    MODE16 = 0,
    // Address size is 32-bit
    MODE32 = 1,
    // Address size is 32-bit
    MODE64 = 2,
}
