use core::cell::Cell;
use core::ffi::c_void;
use std::result::Result;

/// Represents errors that can occur when using the `arena-allocator`.
///
/// The `ArenaError` enum encapsulates different types of errors that might be encountered while
/// interacting with the `Arena` or `TypedArena`. These errors typically arise from issues
/// related to memory reservation, protection, or when the arena runs out of reserved memory.
///
/// # Variants
///
/// - `ReserveFailed(String)`: This error occurs when the initial reservation of virtual memory
///   fails. The associated string provides a description of the underlying issue.
///
/// - `ProtectionFailed(String)`: This error is returned when the memory protection mechanisms
///   fail. This is especially relevant in debug mode, where memory protection is used to detect
///   use-after-free bugs. The associated string provides a detailed explanation of the failure.
///
/// - `OutOfReservedMemory`: This error is triggered when an allocation request exceeds the
///   available reserved memory. It indicates that the arena has run out of its pre-reserved
///   virtual memory and cannot accommodate additional allocations without further action.
#[derive(Debug)]
pub enum ArenaError {
    ReserveFailed(String),
    ProtectionFailed(String),
    OutOfReservedMemory,
}

#[cfg(not(target_os = "windows"))]
mod posix {
    use crate::ArenaError;
    use core::ffi::{c_void, CStr};
    use core::ptr::null_mut;
    use libc::{mmap, mprotect, strerror_r, sysconf};
    use libc::{_SC_PAGESIZE, MAP_ANON, MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE};
    use std::io;

    const MAP_FAILED: *mut c_void = !0 as *mut c_void;

    pub(crate) fn get_page_size() -> usize {
        unsafe { sysconf(_SC_PAGESIZE) as usize }
    }

    fn get_last_error_code() -> i32 {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn get_last_error_message() -> String {
        let err_code = get_last_error_code();
        let mut buf = [0i8; 256];
        unsafe {
            strerror_r(err_code, buf.as_mut_ptr(), buf.len());
            let c_str = CStr::from_ptr(buf.as_ptr());
            c_str.to_string_lossy().into_owned()
        }
    }

    pub(crate) fn reserve_range(size: usize) -> Result<*mut c_void, ArenaError> {
        let ptr = unsafe { mmap(null_mut(), size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0) };
        if ptr == MAP_FAILED {
            return Err(ArenaError::ReserveFailed(get_last_error_message()));
        }
        Ok(ptr)
    }

    pub(crate) fn commit_memory(ptr: *mut c_void, size: usize) -> Result<(), ArenaError> {
        let result = unsafe { mprotect(ptr, size, PROT_READ | PROT_WRITE) };
        if result != 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    pub(crate) fn decommit_memory(ptr: *mut c_void, size: usize) -> Result<(), ArenaError> {
        let result = unsafe { mprotect(ptr, size, PROT_NONE) };
        if result != 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(crate) fn protect_memory(ptr: *mut c_void, size: usize) -> Result<(), ArenaError> {
        let result = unsafe { mprotect(ptr, size, PROT_NONE) };
        if result != 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(crate) fn unprotect_memory(ptr: *mut c_void, size: usize) -> Result<(), ArenaError> {
        if size > 0 {
            let result = unsafe { mprotect(ptr, size, PROT_READ | PROT_WRITE) };
            if result != 0 {
                return Err(ArenaError::ProtectionFailed(get_last_error_message()));
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use crate::ArenaError;
    use core::{ffi::c_void, mem::zeroed};
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr::null_mut};

    const FORMAT_MESSAGE_ALLOCATE_BUFFER: u32 = 0x00000100;
    const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x00001000;
    const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x00000200;

    const MEM_COMMIT: u32 = 0x00001000;
    const MEM_DECOMMIT: u32 = 0x00004000;
    const MEM_RESERVE: u32 = 0x00002000;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_READWRITE: u32 = 0x04;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct SYSTEM_INFO {
        wProcessorArchitecture: u16,
        wReserved: u16,
        dwPageSize: u32,
        lpMinimumApplicationAddress: *mut u8,
        lpMaximumApplicationAddress: *mut u8,
        dwActiveProcessorMask: *mut u64,
        dwNumberOfProcessors: u32,
        dwProcessorType: u32,
        dwAllocationGranularity: u32,
        wProcessorLevel: u16,
        wProcessorRevision: u16,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemInfo(lpSystemInfo: *mut SYSTEM_INFO);
        fn GetLastError() -> u32;
        fn FormatMessageW(
            dwFlags: u32,
            lpSource: *const u16,
            dwMessageId: u32,
            dwLanguageId: u32,
            lpBuffer: *mut u16,
            nSize: u32,
            Arguments: *mut *mut u8,
        ) -> u32;
        fn LocalFree(hMem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
        fn VirtualAlloc(
            lpAddress: *mut core::ffi::c_void,
            dwSize: usize,
            flAllocationType: u32,
            flProtect: u32,
        ) -> *mut core::ffi::c_void;
        fn VirtualProtect(
            lpAddress: *mut core::ffi::c_void,
            dwSize: usize,
            flNewProtect: u32,
            lpflOldProtect: *mut u32,
        ) -> i32;
        fn VirtualFree(lpAddress: *mut core::ffi::c_void, dwSize: usize, dwFreeType: u32) -> i32;
    }

    fn get_system_info() -> SYSTEM_INFO {
        let mut info: SYSTEM_INFO = unsafe { zeroed() };
        unsafe {
            GetSystemInfo(&mut info);
        }
        info
    }

    pub(crate) fn get_page_size() -> usize {
        let info = get_system_info();
        info.dwPageSize as usize
    }

    fn get_last_error_message() -> String {
        unsafe {
            let error_code = GetLastError();
            if error_code == 0 {
                return String::new();
            }

            let mut buf: *mut u16 = null_mut();
            let size = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS,
                null_mut(),
                error_code,
                0,
                &mut buf as *mut *mut u16 as *mut u16,
                0,
                null_mut(),
            );

            if size == 0 {
                return format!("Unknown error code: {}", error_code);
            }

            let message = OsString::from_wide(core::slice::from_raw_parts(buf, size as usize))
                .to_string_lossy()
                .into_owned();
            LocalFree(buf as *mut _);
            message
        }
    }

    pub(crate) fn reserve_range(size: usize) -> Result<*mut c_void, ArenaError> {
        let ptr = unsafe { VirtualAlloc(null_mut(), size, MEM_RESERVE, PAGE_READWRITE) };
        if ptr.is_null() {
            return Err(ArenaError::ReserveFailed(get_last_error_message()));
        }
        Ok(ptr)
    }

    pub(crate) fn commit_memory(
        ptr: *mut core::ffi::c_void,
        size: usize,
    ) -> Result<(), ArenaError> {
        let success = unsafe { VirtualAlloc(ptr, size, MEM_COMMIT, PAGE_READWRITE) };
        if success.is_null() {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    pub(crate) fn decommit_memory(
        ptr: *mut core::ffi::c_void,
        size: usize,
    ) -> Result<(), ArenaError> {
        let success = unsafe { VirtualFree(ptr, size, MEM_DECOMMIT) };
        if success == 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(crate) fn protect_memory(
        ptr: *mut core::ffi::c_void,
        size: usize,
    ) -> Result<(), ArenaError> {
        let mut old_protect = 0u32;
        let success = unsafe { VirtualProtect(ptr, size, PAGE_NOACCESS, &mut old_protect) };
        if success == 0 {
            return Err(ArenaError::ProtectionFailed(get_last_error_message()));
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(crate) fn unprotect_memory(
        ptr: *mut core::ffi::c_void,
        size: usize,
    ) -> Result<(), ArenaError> {
        if size > 0 {
            let mut old_protect = 0u32;
            let success = unsafe { VirtualProtect(ptr, size, PAGE_READWRITE, &mut old_protect) };
            if success == 0 {
                return Err(ArenaError::ProtectionFailed(get_last_error_message()));
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) use posix::*;

#[cfg(target_os = "windows")]
pub(crate) use windows::*;

struct VmRange {
    ptr: *mut c_void,
    reserved_size: usize,
    committed_size: Cell<usize>,
    pos: Cell<usize>,
    page_size: usize,
}

impl VmRange {
    pub fn new(reserved_size: usize) -> Result<Self, ArenaError> {
        let page_size = get_page_size();
        let ptr = reserve_range(std::cmp::max(reserved_size, page_size))?;
        Ok(Self {
            ptr,
            reserved_size,
            committed_size: Cell::new(0),
            pos: Cell::new(0),
            page_size,
        })
    }

    #[inline]
    fn align_pow2(x: usize, b: usize) -> usize {
        (x + b - 1) & !(b - 1)
    }

    /// Allocates a raw memory block in the arena.
    ///
    /// # Safety
    /// The returned data is uninitialized. The caller must ensure that the data is
    /// properly initialized.
    pub(crate) unsafe fn alloc_raw<'a>(
        &'a self,
        size: usize,
        alignment: usize,
    ) -> Result<&'a mut [u8], ArenaError> {
        let pos = self.pos.get();
        let new_pos = pos + Self::align_pow2(size, alignment);
        let committed = self.committed_size.get();

        // If we have already committed enough memory, we can just return a slice
        if new_pos <= committed {
            let return_slice = std::slice::from_raw_parts_mut(self.ptr.add(pos) as *mut u8, size);
            self.pos.set(new_pos);
            return Ok(return_slice);
        }

        // Need to commit more memory
        let needed_commit = Self::align_pow2(new_pos, self.page_size);
        if needed_commit > self.reserved_size {
            return Err(ArenaError::OutOfReservedMemory);
        }

        let commit_size = needed_commit - committed;
        commit_memory(self.ptr.add(committed), commit_size)?;

        self.committed_size.set(needed_commit);
        let return_slice = std::slice::from_raw_parts_mut(self.ptr.add(pos) as *mut u8, size);
        self.pos.set(new_pos);
        Ok(return_slice)
    }

    /// Allocates a raw aligned memory block in the arena, returning a raw pointer.
    ///
    /// Unlike `alloc_raw`, which aligns the *size* of the allocation, this function aligns
    /// the *starting address* of the returned pointer to `alignment` bytes by skipping any
    /// padding needed at the current position.
    ///
    /// # Safety
    /// The returned memory is uninitialized. The caller must ensure that the memory is
    /// properly initialized before use. `alignment` must be a power of two.
    pub(crate) unsafe fn alloc_raw_aligned<'a>(
        &'a self,
        size: usize,
        alignment: usize,
    ) -> Result<&'a mut [u8], ArenaError> {
        let pos = self.pos.get();
        let aligned_pos = Self::align_pow2(pos, alignment);
        let new_pos = aligned_pos + size;
        let needed_commit = Self::align_pow2(new_pos, self.page_size);
        let committed = self.committed_size.get();

        if needed_commit > self.reserved_size {
            return Err(ArenaError::OutOfReservedMemory);
        }

        if new_pos > committed {
            let extra = needed_commit - committed;
            commit_memory(self.ptr.add(committed), extra)?;
            self.committed_size.set(needed_commit);
        }

        let slice = std::slice::from_raw_parts_mut(self.ptr.add(aligned_pos) as *mut u8, size);
        self.pos.set(new_pos);
        Ok(slice)
    }

    /// Allocates an array of `T` elements in the arena.
    ///
    /// # Safety
    /// The returned data is uninitialized. The caller must ensure that the data is
    /// properly initialized.
    pub(crate) unsafe fn alloc_array<'a, T: Sized>(
        &'a self,
        count: usize,
    ) -> Result<&'a mut [T], ArenaError> {
        let size = count * core::mem::size_of::<T>();
        let alignment = core::mem::align_of::<T>();
        let slice = self.alloc_raw(size, alignment)?;
        let ptr = slice.as_mut_ptr() as *mut T;
        Ok(unsafe { std::slice::from_raw_parts_mut(ptr, count) })
    }

    /// Allocates an array of `T` elements in the arena and initializes them with the default
    /// value.
    pub(crate) fn alloc_array_init<'a, T: Default + Sized>(
        &'a self,
        count: usize,
    ) -> Result<&'a mut [T], ArenaError> {
        let size = count * core::mem::size_of::<T>();
        let alignment = core::mem::align_of::<T>();
        let slice = unsafe { self.alloc_raw(size, alignment)? };
        let ptr = slice.as_mut_ptr() as *mut T;
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, count) };

        for v in slice.iter_mut() {
            *v = T::default();
        }

        Ok(slice)
    }

    /// Allocates a single instance of `T` in the arena.
    ///
    /// # Safety
    /// The returned data is uninitialized. The caller must ensure that the data is
    /// properly initialized.
    pub(crate) unsafe fn alloc<'a, T: Sized>(&'a self) -> Result<&'a mut T, ArenaError> {
        let size = core::mem::size_of::<T>();
        let alignment = core::mem::align_of::<T>();
        let slice = self.alloc_raw(size, alignment)?;
        let ptr = slice.as_mut_ptr() as *mut T;
        Ok(unsafe { &mut *ptr })
    }

    pub(crate) fn alloc_init<'a, T: Default + Sized>(&'a self) -> Result<&'a mut T, ArenaError> {
        let size = core::mem::size_of::<T>();
        let alignment = core::mem::align_of::<T>();
        let slice = unsafe { self.alloc_raw(size, alignment)? };
        let ptr = slice.as_mut_ptr() as *mut T;
        unsafe { ptr.write(T::default()) };
        Ok(unsafe { &mut *ptr })
    }

    #[inline]
    pub(crate) fn rewind(&mut self) {
        self.pos.set(0);
    }

    #[cfg(debug_assertions)]
    pub(crate) fn protect(&mut self) {
        protect_memory(self.ptr, self.committed_size.get()).unwrap();
    }

    #[cfg(debug_assertions)]
    pub(crate) fn unprotect(&mut self) {
        unprotect_memory(self.ptr, self.committed_size.get()).unwrap();
    }

    #[inline]
    pub(crate) fn decomit(&mut self) -> Result<(), ArenaError> {
        decommit_memory(self.ptr, self.committed_size.get())?;
        self.committed_size.set(0);
        self.pos.set(0);
        Ok(())
    }
}

/// A memory arena for efficient allocation management.
///
/// The `Arena` struct manages a reserved block of virtual memory, enabling fast, contiguous
/// allocations. This structure is particularly useful in scenarios where many small allocations
/// are required, as it minimizes overhead and fragmentation.
///
/// # Primary Use-Cases
///
/// The `Arena` is designed for two main allocation patterns:
///
/// 1. **Long-Lived Allocations**: When allocations are expected to persist until the end of the
///    program. This use-case benefits from the arena's efficient management of memory, avoiding
///    the overhead of frequent deallocations.
///    
/// 2. **Very Short-Lived Allocations**: When allocations are needed temporarily, and the allocator
///    is "rewinded" after the allocations are no longer needed. This pattern is ideal for scenarios
///    where large numbers of temporary objects are created and discarded in one go, as it allows for quick
///    cleanup and re-use of the allocated memory.
///
/// # Fields
///
/// - `current`: The active `VmRange` that tracks the currently allocated range within the reserved
///   memory. Allocations are performed from this range.
///
/// - `prev`: A secondary `VmRange` used only in debug mode. This range mirrors the `current` range
///   and is protected after being decommitted, allowing detection of use-after-free errors.
///   In release mode, this field is not used, and memory protection is disabled to maximize performance.
///
/// # Usage
///
/// The `Arena` is initialized with a specified size through the `Arena::new` function. While the
/// entire size is reserved in virtual memory, physical memory is only committed in page-sized chunks
/// as needed. This design ensures that the memory footprint remains minimal until actual allocations
/// occur.
///
/// In debug builds, additional memory protection is enabled to catch potential memory safety issues
/// such as use-after-free, though this comes at the cost of increased memory usage. This feature is
/// automatically disabled in release builds for optimal performance.
pub struct Arena {
    current: VmRange,
    //#[cfg(debug_assertions)]
    prev: VmRange,
}

impl Arena {
    /// Initializes a new `Arena` with the specified size. The `size` parameter defines the amount
    /// of reserved virtual memory. It is recommended to choose a large size since this reservation
    /// does not immediately consume physical memory. On a 64-bit system, reserving a few gigabytes
    /// is generally acceptable. Physical memory is committed incrementally in page-sized chunks
    /// as allocations occur.
    ///
    /// In debug mode, decommitted memory is protected to detect use-after-free errors, resulting
    /// in double the memory reservation. This protection is disabled in release mode.
    pub fn new(size: usize) -> Result<Self, ArenaError> {
        let current = VmRange::new(size)?;
        #[cfg(debug_assertions)]
        let prev = VmRange::new(size)?;

        Ok(Self {
            current,
            #[cfg(debug_assertions)]
            prev,
        })
    }

    /// Allocates a raw memory block in the arena.
    ///
    /// This function allocates a block of uninitialized memory within the arena. The size and alignment
    /// of the block are specified by the caller. The allocated memory is contiguous and may be used
    /// for any purpose that requires raw, untyped data.
    ///
    /// # Safety
    /// The returned memory is uninitialized, and it is the caller's responsibility to ensure that
    /// the memory is properly initialized before it is used. Failing to do so may result in undefined
    /// behavior.
    pub unsafe fn alloc_raw<'a>(
        &'a self,
        size: usize,
        alignment: usize,
    ) -> Result<&'a mut [u8], ArenaError> {
        self.current.alloc_raw(size, alignment)
    }

    /// Allocates a raw aligned memory block in the arena, returning a raw pointer.
    ///
    /// This function allocates `size` bytes of uninitialized memory whose starting address is
    /// aligned to `alignment` bytes. Unlike `alloc_raw`, which only rounds the allocation size
    /// to the alignment boundary, this function ensures the returned pointer itself satisfies
    /// the alignment requirement by advancing past any padding at the current position.
    ///
    /// # Safety
    /// The returned memory is uninitialized, and it is the caller's responsibility to ensure
    /// that the memory is properly initialized before it is used. `alignment` must be a power
    /// of two. Failing to initialize the memory or passing a non-power-of-two alignment may
    /// result in undefined behavior.
    pub unsafe fn alloc_raw_aligned<'a>(
        &'a self,
        size: usize,
        alignment: usize,
    ) -> Result<&'a mut [u8], ArenaError> {
        self.current.alloc_raw_aligned(size, alignment)
    }

    /// Allocates an array of `T` elements in the arena.
    ///
    /// This function allocates uninitialized memory for an array of elements of type `T`. The number
    /// of elements is specified by the `count` parameter. The memory is contiguous and properly aligned
    /// for the type `T`.
    ///
    /// # Safety
    /// The returned array is uninitialized, and it is the caller's responsibility to initialize the
    /// elements before use. Using uninitialized data can lead to undefined behavior. After the arena
    /// is rewound, all references to this array become invalid.
    pub unsafe fn alloc_array<'a, T: Sized>(
        &'a self,
        count: usize,
    ) -> Result<&'a mut [T], ArenaError> {
        self.current.alloc_array(count)
    }

    /// Allocates a single instance of `T` in the arena.
    ///
    /// This function allocates uninitialized memory for a single instance of type `T`.
    ///
    /// # Safety
    /// The returned instance is uninitialized, and the caller must ensure that it is initialized
    /// before any use. Uninitialized memory can lead to undefined behavior if accessed.
    pub unsafe fn alloc<'a, T: Sized>(&'a self) -> Result<&'a mut T, ArenaError> {
        self.current.alloc()
    }

    /// Allocates a single instance of `T` in the arena and initializes it with the default value.
    ///
    /// This function allocates memory for a single instance of type `T` and initializes it using
    /// `T::default()`.
    pub fn alloc_init<'a, T: Default + Sized>(&'a self) -> Result<&'a mut T, ArenaError> {
        self.current.alloc_init()
    }

    /// Allocates an array of `T` elements in the arena and initializes them with the default value.
    ///
    /// This function allocates memory for an array of elements of type `T`, and initializes each
    /// element using `T::default()`.
    pub fn alloc_array_init<'a, T: Default + Sized>(
        &'a self,
        count: usize,
    ) -> Result<&'a mut [T], ArenaError> {
        self.current.alloc_array_init(count)
    }

    /// Rewinds the arena to its initial state, consuming self and returning a new arena.
    ///
    /// This method resets the allocation position to the start of the arena without deallocating
    /// the memory. By consuming `self`, this ensures that all references to previously allocated
    /// memory are dropped before the arena can be used again, providing compile-time safety against
    /// use-after-rewind bugs.
    ///
    /// # Memory Safety
    ///
    /// The following code will not compile because the reference `t` cannot outlive the rewind:
    ///
    /// ```compile_fail
    /// use arena_allocator::Arena;
    ///
    /// let mut arena = Arena::new(16 * 1024).unwrap();
    /// let t = arena.alloc_array_init::<u32>(10).unwrap();
    /// let u = &t[0];  // Borrow from t
    /// arena = arena.rewind();  // Error: cannot move `arena` while borrowed
    /// println!("{}", u);  // u keeps the borrow alive
    /// ```
    ///
    /// The correct usage requires dropping all references before rewind:
    ///
    /// ```
    /// use arena_allocator::Arena;
    ///
    /// let mut arena = Arena::new(16 * 1024).unwrap();
    /// {
    ///     let t = arena.alloc_init::<u32>().unwrap();
    ///     *t = 42;
    ///     // t goes out of scope here
    /// }
    /// arena = arena.rewind();  // OK: no references exist
    /// let t2 = arena.alloc_init::<u32>().unwrap();
    /// *t2 = 100;
    /// ```
    ///
    /// # Usage
    ///
    /// This method is particularly useful in scenarios where the arena is used for very short-lived
    /// allocations that are discarded en masse. By rewinding the arena, the allocator can quickly
    /// reset and re-use the reserved memory without the overhead of deallocation and reallocation.
    ///
    /// In debug mode, the old memory is protected to catch bugs, while in release mode this
    /// protection is disabled for optimal performance.
    #[cfg(debug_assertions)]
    pub fn rewind(mut self) -> Self {
        self.current.protect();

        std::mem::swap(&mut self.current, &mut self.prev);

        // Unprotect the new current range and rewind the position to the start
        self.current.unprotect();
        self.current.rewind();
        self
    }

    #[cfg(not(debug_assertions))]
    pub fn rewind(mut self) -> Self {
        self.current.rewind();
        self
    }
}

impl Drop for Arena {
    #[cfg(debug_assertions)]
    fn drop(&mut self) {
        self.current.decomit().unwrap();
        self.prev.decomit().unwrap();
    }

    #[cfg(not(debug_assertions))]
    fn drop(&mut self) {
        self.current.decomit().unwrap();
    }
}

/// A type-specific memory arena for efficient allocation of `T` elements.
///
/// `TypedArena` is a specialized memory allocator designed for managing objects of a single type `T`.
/// It builds upon the underlying `Arena`, providing type safety and automatic initialization of
/// allocated objects using `T::default()`. This makes it ideal for scenarios where a large number of
/// objects of type `T` need to be allocated efficiently, either for long-term storage or for
/// short-lived usage with rapid recycling.
///
/// # Type Parameters
///
/// - `T`: The type of objects that this arena will manage. `T` must implement the `Default` and
///   `Sized` traits, ensuring that instances can be created with default values and that their
///   size is known at compile-time.
///
/// # Primary Use-Cases
///
/// `TypedArena` is particularly useful in situations where:
///
/// 1. **Long-Lived Allocations**: Objects are allocated once and used until the end of the program.
/// 2. **Short-Lived Allocations**: Objects are allocated and then quickly discarded, with the
///    entire arena being rewound for reuse. This is efficient for temporary data structures
///    that need to be quickly recycled.
///
/// # Example
///
/// ```rust
/// use arena_allocator::TypedArena;
///
/// let mut arena = TypedArena::<u32>::new(1024 * 1024).unwrap();
/// let item = arena.alloc().unwrap();
/// *item = 42;
///
/// let array = arena.alloc_array(10).unwrap();
/// for i in 0..10 {
///     array[i] = i as u32;
/// }
///
/// arena.rewind(); // All previous allocations are now invalid.
/// ```
pub struct TypedArena<T: Default + Sized> {
    arena: Arena,
    ptr_type: core::marker::PhantomData<T>,
}

impl<T: Default + Sized> TypedArena<T> {
    /// Creates a new `TypedArena` with the specified size.
    ///
    /// The `size` parameter specifies the amount of memory to reserve in the arena. It is
    /// recommended to choose a large size, especially for scenarios where many objects of
    /// type `T` will be allocated. The reserved memory is not immediately committed, so
    /// reserving more than necessary does not consume physical memory until allocations occur.
    ///
    /// # Errors
    /// This function will return an `ArenaError` if the underlying memory reservation fails.
    pub fn new(size: usize) -> Result<Self, ArenaError> {
        Ok(Self {
            arena: Arena::new(size)?,
            ptr_type: core::marker::PhantomData,
        })
    }

    /// Allocates a single instance of `T` in the arena and initializes it with the default value.
    ///
    /// This function allocates memory for an instance of `T` and initializes it using `T::default()`.
    /// The returned reference points to the initialized object, which can be used immediately.
    ///
    /// # Errors
    /// This function will return an `ArenaError` if the memory allocation fails.
    pub fn alloc<'a>(&'a self) -> Result<&'a mut T, ArenaError> {
        self.arena.alloc_init()
    }

    /// Allocates an array of `T` elements in the arena and initializes them with the default value.
    ///
    /// This function allocates memory for an array of `T` elements and initializes each element using
    /// `T::default()`. The returned slice points to the initialized array, which can be used immediately.
    ///
    /// # Errors
    /// This function will return an `ArenaError` if the memory allocation fails.
    pub fn alloc_array<'a>(&'a self, count: usize) -> Result<&'a mut [T], ArenaError> {
        self.arena.alloc_array_init(count)
    }

    /// Rewinds the arena to its initial state, consuming self and returning a new arena.
    ///
    /// This method resets the arena, allowing it to be reused for new allocations. By consuming
    /// `self`, this ensures that all references to previously allocated objects are dropped before
    /// the arena can be used again, providing compile-time safety against use-after-rewind bugs.
    ///
    /// # Compile-Time Safety
    ///
    /// The following code will not compile because the reference cannot outlive the rewind:
    ///
    /// ```compile_fail
    /// use arena_allocator::TypedArena;
    ///
    /// let mut arena = TypedArena::<u32>::new(16 * 1024).unwrap();
    /// let item = arena.alloc_array(10).unwrap();
    /// let u = &item[0];  // Borrow from item  
    /// arena = arena.rewind();  // Error: cannot move `arena` while borrowed
    /// println!("{}", u);  // u keeps the borrow alive
    /// ```
    ///
    /// The correct usage requires dropping all references before rewind:
    ///
    /// ```
    /// use arena_allocator::TypedArena;
    ///
    /// let mut arena = TypedArena::<u32>::new(16 * 1024).unwrap();
    /// {
    ///     let item = arena.alloc().unwrap();
    ///     *item = 42;
    ///     // item goes out of scope here
    /// }
    /// arena = arena.rewind();  // OK: no references exist
    /// let item2 = arena.alloc().unwrap();
    /// *item2 = 100;
    /// ```
    ///
    /// # Usage
    /// `rewind` is particularly useful in scenarios where the arena is used for temporary allocations
    /// that need to be quickly discarded and recycled.
    pub fn rewind(self) -> Self {
        Self {
            arena: self.arena.rewind(),
            ptr_type: core::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_arena() {
        let arena = Arena::new(16 * 1024).unwrap();
        let slice = unsafe { arena.alloc_raw(1024, 16).unwrap() };
        assert_eq!(slice.len(), 1024);
        assert_eq!(slice.as_ptr() as usize % 16, 0);
        assert!(slice.as_ptr() != std::ptr::null_mut());
    }

    #[test]
    fn test_arena_aligned() {
        let arena = Arena::new(16 * 1024).unwrap();
        // Misalign the position by allocating 1 byte first
        let _ = unsafe { arena.alloc_raw(1, 1).unwrap() };
        let slice = unsafe { arena.alloc_raw_aligned(64, 64).unwrap() };
        assert_eq!(slice.len(), 64);
        assert_eq!(slice.as_ptr() as usize % 64, 0);
    }

    #[test]
    fn test_fail_reserve() {
        let result = Arena::new(usize::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn test_fail_commit() {
        let size = 16 * 1024;
        let arena = Arena::new(size).unwrap();
        let result = unsafe { arena.alloc_raw(size * 2, 16) };
        assert!(result.is_err());
    }

    #[test]
    fn test_no_aliasing() {
        // This test verifies that multiple allocations don't overlap/alias
        let arena = Arena::new(16 * 1024).unwrap();

        // Allocate two u32 values - now we can have both at once!
        let a = arena.alloc_init::<u32>().unwrap();
        let b = arena.alloc_init::<u32>().unwrap();

        // Write different values to each
        *a = 42;
        *b = 99;

        // Verify they maintained their separate values (no aliasing)
        assert_eq!(*a, 42);
        assert_eq!(*b, 99);

        // Verify they point to different memory locations
        let ptr_a = a as *const u32;
        let ptr_b = b as *const u32;
        assert_ne!(ptr_a, ptr_b);
    }

    #[test]
    fn test_typed_arena() {
        let arena = TypedArena::<u32>::new(32 * 1024).unwrap();
        let single = arena.alloc().unwrap();
        assert_eq!(*single, 0);
        *single = 42;
        assert_eq!(*single, 42);

        let array = arena.alloc_array(1024).unwrap();
        assert_eq!(array.len(), 1024);
        for i in 0..1024 {
            assert_eq!(array[i], 0);
            array[i] = i as u32;
        }
        for i in 0..1024 {
            assert_eq!(array[i], i as u32);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[cfg(test)]
mod macos_linux_tests {
    use super::*;
    use libc::{fork, waitpid, SIGSEGV, WIFEXITED, WIFSIGNALED};
    use std::process;

    #[test]
    fn test_crash_handling() {
        unsafe {
            let pid = fork();
            if pid == -1 {
                panic!("Failed to fork process");
            } else if pid == 0 {
                let arena = TypedArena::<u32>::new(32 * 1024).unwrap();
                let single_ptr: *mut u32;
                {
                    let single = arena.alloc().unwrap();
                    *single = 42;
                    single_ptr = single as *mut u32;
                }
                _ = arena.rewind();
                *single_ptr = 43; // will crash here as trying to write to protected memory
                println!("Single: {}", *single_ptr);
            } else {
                // Parent process
                let mut status = 0;
                waitpid(pid, &mut status, 0);
                if WIFSIGNALED(status) && libc::WTERMSIG(status) == SIGSEGV {
                    println!("Child process crashed as expected");
                } else if WIFEXITED(status) {
                    println!("Child process exited normally, but crash was expected");
                    process::exit(1); // Mark test as failed if child didn't crash
                }
            }
        }
    }
}
