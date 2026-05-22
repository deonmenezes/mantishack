//! Composable widgets used by [`crate::ui`].
//!
//! Placeholder module — subsequent tasks fill in:
//! - `markdown` — pulldown-cmark + syntect-driven assistant rendering
//! - `input` — multiline edit buffer with history scroll
//! - `slash` — dropdown autocomplete overlay
//! - `picker` — full-screen session list selector
//!
//! For now this module exists so the public API of the crate is
//! stable across the parallel tasks: each widget gets its own
//! submodule that the renderer pulls in.

pub mod markdown;
pub mod picker;
pub mod slash;
