mod nt_thread;
mod nt_apc;
mod nt_section;
mod nt_callback;
mod nt_suspended;

pub type InjectFn = fn(&[u8]) -> bool;

pub struct Technique {
    pub name: &'static str,
    pub func: InjectFn,
}

pub static REGISTRY: &[Technique] = &[
    Technique { name: "nt_thread", func: nt_thread::run },
    Technique { name: "nt_apc", func: nt_apc::run },
    Technique { name: "nt_section", func: nt_section::run },
    Technique { name: "nt_callback", func: nt_callback::run },
    Technique { name: "nt_suspended", func: nt_suspended::run },
];
