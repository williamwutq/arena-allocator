[![Build Status](https://github.com/emoon/arena-allocator/workflows/Rust/badge.svg)](https://github.com/emoon/arena-allocator/actions?workflow=Rust)
[![Crates.io](https://img.shields.io/crates/v/arena-allocator.svg)](https://crates.io/crates/arena-allocator)
[![Documentation](https://docs.rs/arena-allocator/badge.svg)](https://docs.rs/arena-allocator)

A fast linear/arena allocator for Rust. Reserves a large virtual address range upfront and commits physical pages on demand, making large reservations (several GB) cheap.

Two main use cases:
1. Long-lived allocations — allocate once, use for the program's lifetime.
2. Temporary allocations — allocate freely, then call `rewind()` to reset the arena in one step.

## Safety

Use-after-rewind is prevented at two levels:

- Compile time — `rewind()` consumes the arena (`self`), so the borrow checker rejects any live references at the call site:
  ```rust
  let arena = Arena::new(1 << 30)?;
  let slice = arena.alloc_array_init::<u32>(10)?;
  arena = arena.rewind(); // compile error: arena is borrowed by `slice`
  ```
  Dropping all references before rewinding is required by the type system.

- Debug mode — after `rewind()`, the old memory pages are `mprotect`'d as `PROT_NONE`. Any stale raw pointer access crashes immediately.

## Usage

```toml
[dependencies]
arena-allocator = "0.1"
```

Example:

```rust
use arena_allocator::{Arena, TypedArena, ArenaError};

fn main() -> Result<(), ArenaError> {
    let arena = Arena::new(1 * 1024 * 1024 * 1024)?;

    let num = arena.alloc_init::<u32>()?;
    *num = 42;

    let array = arena.alloc_array_init::<u32>(10)?;
    array[0] = 1;

    // Drop references before rewinding
    _ = num;
    _ = array;
    let arena = arena.rewind();

    Ok(())
}
```

`TypedArena<T>` provides the same API restricted to a single type:

```rust
use arena_allocator::TypedArena;

let arena = TypedArena::<u32>::new(1 * 1024 * 1024 * 1024)?;
let item = arena.alloc()?;
*item = 42;
# Ok::<(), arena_allocator::ArenaError>(())
```

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
