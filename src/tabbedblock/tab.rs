//! This module holds the [`tab`] element and its related configuration types.
//! A tab is a piece of [`Block`](crate::widgets::Block) configuration.

use strum::{Display, EnumString};

use ratatui::{layout::Alignment, text::Line};

/// A [`Block`](crate::widgets::Block) tab.
///
/// It can be aligned (see [`Alignment`]) and positioned (see [`Position`]).
///
/// # Example
///
/// tab with no style.
/// ```
/// use ratatui::widgets::block::tab;
///
/// tab::from("tab");
/// ```
///
/// Blue tab on a white background (via [`Stylize`](crate::style::Stylize) trait).
/// ```
/// use ratatui::{prelude::*, widgets::block::*};
///
/// tab::from("tab".blue().on_white());
/// ```
///
/// tab with multiple styles (see [`Line`] and [`Stylize`](crate::style::Stylize)).
/// ```
/// use ratatui::{prelude::*, widgets::block::*};
///
/// tab::from(Line::from(vec!["Q".white().underlined(), "uit".gray()]));
/// ```
///
/// Complete example
/// ```
/// use ratatui::{
///     prelude::*,
///     widgets::{block::*, *},
/// };
///
/// tab::from("tab")
///     .position(Position::Top)
///     .alignment(Alignment::Right);
/// ```
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct Tab<'a> {
    /// tab content
    pub content: Line<'a>,

    /// tab index
    pub index: usize,

    /// tab alignment
    ///
    /// If [`None`], defaults to the alignment defined with
    /// [`Block::tab_alignment`](crate::widgets::Block::tab_alignment) in the associated
    /// [`Block`](crate::widgets::Block).
    pub alignment: Option<Alignment>,

    /// tab position
    ///
    /// If [`None`], defaults to the position defined with
    /// [`Block::tab_position`](crate::widgets::Block::tab_position) in the associated
    /// [`Block`](crate::widgets::Block).
    pub position: Option<Position>,
}

/// Defines the [tab](crate::widgets::block::tab) position.
///
/// The tab can be positioned on top or at the bottom of the block.
/// Defaults to [`Position::Top`].
///
/// # Example
///
/// ```
/// use ratatui::widgets::{block::*, *};
///
/// Block::new().tab(tab::from("tab").position(Position::Bottom));
/// ```
#[derive(Debug, Default, Display, EnumString, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Position {
    /// Position the tab at the top of the block.
    ///
    /// This is the default.
    #[default]
    Top,
    /// Position the tab at the bottom of the block.
    Bottom,
}

impl<'a> Tab<'a> {
    /// Set the tab content.
    pub fn content<T>(mut self, content: T) -> Tab<'a>
    where
        T: Into<Line<'a>>,
    {
        self.content = content.into();
        self
    }

    /// Set the tab alignment.
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn alignment(mut self, alignment: Alignment) -> Tab<'a> {
        self.alignment = Some(alignment);
        self
    }

    /// Set the tab position.
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn position(mut self, position: Position) -> Tab<'a> {
        self.position = Some(position);
        self
    }
}

impl<'a, T> From<T> for Tab<'a>
where
    T: Into<Line<'a>>,
{
    fn from(value: T) -> Self {
        Self::default().content(value.into())
    }
}
