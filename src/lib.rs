use memory_addr::{PhysAddr, VirtAddr};

const MAXVA: usize = 1 << (9 + 9 + 9 + 12 - 1);

/// A pagetable struct for Rv39
pub struct PageTable {
    pa: PhysAddr,
    pgtbl: *mut RawPageTable,
}

#[repr(C, align(4096))]
struct RawPageTable {
    entries: [RawPageTableEntry; 512]
}

impl RawPageTable {
    pub fn new() -> PageTable {
        let pgtbl = Box::into_raw(Box::new(
                Self {
                    entries: [RawPageTableEntry::zero(); 512],
                }));
        let pa = PhysAddr::from_usize(pgtbl as usize);
        PageTable { pa, pgtbl }
    }

    fn get_entry(&mut self, level: u8, va: VirtAddr) -> &mut RawPageTableEntry {
        &mut self.entries[(va.as_usize() >> (12 + 9 * level)) & 0x1FF]
    }

    /// Return the address of the PTE in page table
    /// that corresponds to virtual address va
    pub fn walk(&mut self, va: VirtAddr, alloc: bool) -> Result<&RawPageTableEntry, ()> {
        if va.as_usize() >= MAXVA {
            return Err(())
        }

        let mut pagetable = self as *mut RawPageTable;
        unsafe {
            for level in (1..3).rev() {
                let entry = (*pagetable).get_entry(level, va);
                if entry.is_v() {
                    pagetable = entry.get_pa().as_usize() as *mut RawPageTable;
                } else {
                    if !alloc {
                        return Err(());
                    }
                    let new_pagetable = RawPageTable::new();
                    entry.set(new_pagetable.pa);
                    pagetable = new_pagetable.pgtbl;
                }
            }
            Ok((*pagetable).get_entry(0, va))
        }
    }

    /// look up a virtual address, return the physical address,
    /// or 0 if not mapped
    /// Can only be used to look up user pages
    pub fn walkaddr(&mut self, va: VirtAddr) -> Result<PhysAddr, ()> {
        if va.as_usize() >= MAXVA {
            return Err(());
        }

        let walk_result = self.walk(va, false);
        if let Ok(pte) = walk_result {
            Ok(pte.get_pa())
        } else {
            Err(())
        }
    }

    /// Recursively free page-table pages.
    /// All leaf mappings must already have been removed.
    pub fn freewalk(&mut self) {
        // there are 2^9 = 512 PTEs in a page table.
        for i in 0..512 {
            let pte = &mut self.entries[0];
            if pte.is_v() && !pte.is_r() && !pte.is_w() && !pte.is_x() {
                // this PTE points to a lower-level page table.
                unsafe {
                    let child = pte.get_pa().as_usize() as *mut Self;
                    (*child).freewalk();
                }
                pte.0 = 0;
            } else if pte.is_v() {
                todo!()
            }
        }
        unsafe {
            drop(Box::from_raw(self as *mut Self));
        }
    }
}

#[derive(Copy, Clone)]
#[repr(transparent)]
struct RawPageTableEntry(usize);

impl RawPageTableEntry {
    const PTE_V: usize = 1 << 0;
    const PTE_R: usize = 1 << 1;
    const PTE_W: usize = 1 << 2;
    const PTE_X: usize = 1 << 3;
    const PTE_U: usize = 1 << 4;

    const fn zero() -> Self {
        Self(0)
    }

    const fn set(&mut self, pa: PhysAddr) {
        self.0 = (pa.as_usize() >> 12) << 10 | Self::PTE_V;
    }

    const fn get_flags(&self) -> usize {
        self.0 & 0xFFF
    }

    const fn is_v(&self) -> bool {
        self.get_flags() & Self::PTE_V == Self::PTE_V
    }

    const fn is_r(&self) -> bool {
        self.get_flags() & Self::PTE_R == Self::PTE_R
    }

    const fn is_w(&self) -> bool {
        self.get_flags() & Self::PTE_W == Self::PTE_W
    }

    const fn is_x(&self) -> bool {
        self.get_flags() & Self::PTE_X == Self::PTE_X
    }

    const fn is_u(&self) -> bool {
        self.get_flags() & Self::PTE_U == Self::PTE_U
    }

    const fn get_pa(&self) -> PhysAddr {
        PhysAddr::from_usize((self.0 >> 10) << 12)
    }
}
