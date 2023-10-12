use std::ops::AddAssign;

pub struct NumberAllocator<N: Num> {
    next: N,
}

impl<N: Num> NumberAllocator<N> {
    pub fn new() -> Self {
        Self { next: N::ZERO }
    }

    pub fn allocate(&mut self) -> N {
        let next = self.next;
        self.next += N::ONE;
        next
    }
}

pub trait Num: Copy + AddAssign {
    const ZERO: Self;
    const ONE: Self;
}

impl Num for u32 {
    const ZERO: Self = 0;
    const ONE: Self = 1;
}

impl Num for usize {
    const ZERO: Self = 0;
    const ONE: Self = 1;
}