#![warn(missing_docs)]
//! Elements related to the `TabbedBlock` base widget.
//!
//! This holds everything needed to display and configure a [`TabbedBlock`].
//!
//! In its simplest form, a `TabbedTabbedBlock` is a [border](Borders) around another widget. It also
//! has tabs along the top, and implements many of the functionality of [tabs](Tabs).

use strum::{Display, EnumString};

use super::tab::{Position, Tab};

use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Rect},
    style::{Style, Styled},
    symbols::line,
    text::Line,
    widgets::{Borders, Clear, Widget},
};

/// The type of tabs of a [`TabbedBlock`].
///
/// See the [`tabstyle`](TabbedBlock::borders) method of `TabbedBlock` to configure its borders.
#[derive(Debug, Default, Display, EnumString, Clone, Copy, Eq, PartialEq, Hash)]
pub enum TabType {
    /// Text sits inside tabs.
    ///
    /// This is the default
    ///
    /// # Example
    ///
    /// ```plain
    /// ┌───────┐ ┌───────┐ ┌───────┐
    /// │ Tab 1 │ │ Tab 2 │ │ Tab 3 │
    /// ┘       └─┴───────┴─┴───────┴
    /// ```
    #[default]
    Full,
    /// Text sits on tabs. Selected item is framed.
    ///
    /// # Example
    ///
    /// ```plain
    /// ┌┤Tab 1├┐ ┌ Tab 2 ┐ ┌ Tab 3 ┐
    /// ┘       └─┴───────┴─┴───────┴
    /// ```
    Concise,
}
/// The type of border of a [`TabbedBlock`].
///
/// See the [`borders`](TabbedBlock::borders) method of `TabbedBlock` to configure its borders.
#[derive(Debug, Default, Display, EnumString, Clone, Copy, Eq, PartialEq, Hash)]
pub enum BorderType {
    /// A plain, simple border.
    ///
    /// This is the default
    ///
    /// # Example
    ///
    /// ```plain
    /// ┌───────┐
    /// │       │
    /// └───────┘
    /// ```
    #[default]
    Plain,
    /// A plain border with rounded corners.
    ///
    /// # Example
    ///
    /// ```plain
    /// ╭───────╮
    /// │       │
    /// ╰───────╯
    /// ```
    Rounded,
    /// A doubled border.
    ///
    /// Note this uses one character that draws two lines.
    ///
    /// # Example
    ///
    /// ```plain
    /// ╔═══════╗
    /// ║       ║
    /// ╚═══════╝
    /// ```
    Double,
    /// A thick border.
    ///
    /// # Example
    ///
    /// ```plain
    /// ┏━━━━━━━┓
    /// ┃       ┃
    /// ┗━━━━━━━┛
    /// ```
    Thick,
}

impl BorderType {
    /// Convert this `BorderType` into the corresponding [`Set`](line::Set) of line symbols.
    pub const fn border_symbols(border_type: BorderType) -> line::Set {
        match border_type {
            BorderType::Plain => line::NORMAL,
            BorderType::Rounded => line::ROUNDED,
            BorderType::Double => line::DOUBLE,
            BorderType::Thick => line::THICK,
        }
    }

    /// Convert this `BorderType` into the corresponding [`Set`](border::Set) of line symbols.
    pub const fn to_border_set(self) -> line::Set {
        Self::border_symbols(self)
    }
}

/// Defines the padding of a [`TabbedBlock`].
///
/// See the [`padding`](TabbedBlock::padding) method of [`TabbedBlock`] to configure its padding.
///
/// This concept is similar to [CSS padding](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_box_model/Introduction_to_the_CSS_box_model#padding_area).
///
/// **NOTE**: Terminal cells are often taller than they are wide, so to make horizontal and vertical
/// padding seem equal, doubling the horizontal padding is usually pretty good.
///
/// # Example
///
/// ```
/// use ratatui::{prelude::*, widgets::*};
///
/// Padding::uniform(1);
/// Padding::horizontal(2);
/// ```
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Padding {
    /// Left padding
    pub left: u16,
    /// Right padding
    pub right: u16,
    /// Top padding
    pub top: u16,
    /// Bottom padding
    pub bottom: u16,
}

impl Padding {
    /// Creates a new `Padding` by specifying every field individually.
    pub const fn new(left: u16, right: u16, top: u16, bottom: u16) -> Self {
        Padding {
            left,
            right,
            top,
            bottom,
        }
    }

    /// Creates a `Padding` of 0.
    ///
    /// This is also the default.
    pub const fn zero() -> Self {
        Padding {
            left: 0,
            right: 0,
            top: 0,
            bottom: 0,
        }
    }

    /// Defines the [`left`](Padding::left) and [`right`](Padding::right) padding.
    ///
    /// This leaves [`top`](Padding::top) and [`bottom`](Padding::bottom) to `0`.
    pub const fn horizontal(value: u16) -> Self {
        Padding {
            left: value,
            right: value,
            top: 0,
            bottom: 0,
        }
    }

    /// Defines the [`top`](Padding::top) and [`bottom`](Padding::bottom) padding.
    ///
    /// This leaves [`left`](Padding::left) and [`right`](Padding::right) at `0`.
    pub const fn vertical(value: u16) -> Self {
        Padding {
            left: 0,
            right: 0,
            top: value,
            bottom: value,
        }
    }

    /// Applies the same value to every `Padding` field.
    pub const fn uniform(value: u16) -> Self {
        Padding {
            left: value,
            right: value,
            top: value,
            bottom: value,
        }
    }
}

/// Base widget to be used to display a box border around all [upper level ones](crate::widgets).
///
/// The borders can be configured with [`TabbedBlock::borders`] and others. A TabbedBlock can have multiple
/// [`Tab`] using [`TabbedBlock::tab`]. It can also be [styled](TabbedBlock::style) and
/// [padded](TabbedBlock::padding).
///
/// # Examples
///
/// ```
/// use ratatui::{prelude::*, widgets::*};
///
/// TabbedBlock::default()
///     .tab("TabbedBlock")
///     .borders(Borders::LEFT | Borders::RIGHT)
///     .border_style(Style::default().fg(Color::White))
///     .border_type(BorderType::Rounded)
///     .style(Style::default().bg(Color::Black));
/// ```
///
/// You may also use multiple tabs like in the following:
/// ```
/// use ratatui::{
///     prelude::*,
///     widgets::{TabbedBlock::*, *},
/// };
///
/// TabbedBlock::default()
///     .tab("tab 1")
///     .tab(tab::from("tab 2").position(Position::Bottom));
/// ```
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct TabbedBlock<'a> {
    /// List of tabs
    tabs: Vec<Tab<'a>>,
    /// The style to be patched to all tabs of the TabbedBlock
    tabs_style: Style,
    /// The default alignment of the tabs that don't have one
    tabs_alignment: Alignment,
    /// The default position of the tabs that don't have one
    tabs_position: Position,
    /// The current tab showing
    current_tab: usize,
    /// Tab style
    tabs_type: TabType,
    /// Visible borders
    borders: Borders,
    /// Border style
    border_style: Style,
    /// The symbols used to render the border. The default is plain lines but one can choose to
    /// have rounded or doubled lines instead or a custom set of symbols
    border_set: line::Set,
    /// Widget style
    style: Style,
    /// TabbedBlock padding
    padding: Padding,
}

impl<'a> TabbedBlock<'a> {
    /// Creates a new TabbedBlock with no [`Borders`] or [`Padding`].
    pub const fn new() -> Self {
        Self {
            tabs: Vec::new(),
            tabs_style: Style::new(),
            tabs_alignment: Alignment::Left,
            tabs_position: Position::Top,
            current_tab: 0,
            tabs_type: TabType::Full,
            borders: Borders::TOP,
            border_style: Style::new(),
            border_set: BorderType::Plain.to_border_set(),
            style: Style::new(),
            padding: Padding::zero(),
        }
    }

    /// Adds a tab to the TabbedBlock.
    ///
    /// The `tab` function allows you to add a tab to the TabbedBlock. You can call this function
    /// multiple times to add multiple tabs.
    ///
    /// Each tab will be rendered with a single space separating tabs that are in the same
    /// position or alignment. When both centered and non-centered tabs are rendered, the centered
    /// space is calculated based on the full width of the TabbedBlock, rather than the leftover width.
    ///
    /// You can provide any type that can be converted into [`tab`] including: strings, string
    /// slices (`&str`), borrowed strings (`Cow<str>`), [spans](crate::text::Span), or vectors of
    /// [spans](crate::text::Span) (`Vec<Span>`).
    ///
    /// By default, the tabs will avoid being rendered in the corners of the TabbedBlock but will align
    /// against the left or right edge of the TabbedBlock if there is no border on that edge.
    /// The following demonstrates this behavior, notice the second tab is one character off to
    /// the left.
    ///
    /// ```plain
    ///  ┌───────┐ ┌───────┐ ┌───────┐
    ///  │ Tab 1 │ │ Tab 2 │ │ Tab 3 │
    /// ┌┘       └─┴───────┴─┴───────┴───
    ///    With a left border
    ///
    /// ┌───────┐ ┌───────┐ ┌───────┐
    /// │ Tab 1 │ │ Tab 2 │ │ Tab 3 │
    /// ┘       └─┴───────┴─┴───────┴───
    ///    Without a left border
    ///
    /// ```
    ///
    /// Note: If the TabbedBlock is too small and multiple tabs overlap, the border might get cut off at
    /// a corner.
    ///
    /// # Example
    ///
    /// The following example demonstrates:
    /// - Default tab alignment
    /// - Multiple tabs (notice "Center" is centered according to the full with of the TabbedBlock, not
    ///   the leftover space)
    /// - Two tabs with the same alignment (notice the left tabs are separated)
    /// ```
    /// use ratatui::{
    ///     prelude::*,
    ///     widgets::{TabbedBlock::*, *},
    /// };
    ///
    /// TabbedBlock::default()
    ///     .tab("tab") // By default in the top left corner
    ///     .tab(tab::from("Left").alignment(Alignment::Left)) // also on the left
    ///     .tab(tab::from("Right").alignment(Alignment::Right))
    ///     .tab(tab::from("Center").alignment(Alignment::Center));
    /// // Renders
    /// // ┌tab─Left────Center─────────Right┐
    /// ```
    ///
    /// # See also
    ///
    /// tabs attached to a TabbedBlock can have default behaviors. See
    /// - [`TabbedBlock::tab_style`]
    /// - [`TabbedBlock::tab_alignment`]
    /// - [`TabbedBlock::tab_position`]
    pub fn tab<T>(mut self, tab: T) -> TabbedBlock<'a>
    where
        T: Into<Tab<'a>>,
    {
        self.tabs.push(tab.into());
        self.tabs.last_mut().unwrap().index = self.tabs.len() - 1;
        self
    }

    /// Sets the selected tab.
    ///
    /// The first tab has index 0 (this is also the default index).
    /// The selected tab can have a different style with [`Tabs::highlight_style`].
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn select(mut self, selected: usize) -> TabbedBlock<'a> {
        self.current_tab = selected;
        self
    }

    /// Applies the style to all tabs.
    ///
    /// If a [`tab`] already has a style, the tab's style will add on top of this one.
    #[must_use = "method moves the value of self and returns the modified value"]
    pub const fn tab_style(mut self, style: Style) -> TabbedBlock<'a> {
        self.tabs_style = style;
        self
    }

    /// Applies the type to all tabs.
    ///
    /// If a [`tab`] already has a type, the tab's style will add on top of this one.
    #[must_use = "method moves the value of self and returns the modified value"]
    pub const fn tab_type(mut self, tab_type: TabType) -> TabbedBlock<'a> {
        self.tabs_type = tab_type;
        self
    }

    /// Sets the default [`Alignment`] for all TabbedBlock tabs.
    ///
    /// tabs that explicitly set an [`Alignment`] will ignore this.
    ///
    /// # Example
    ///
    /// This example aligns all tabs in the center except the "right" tab which explicitly sets
    /// [`Alignment::Right`].
    /// ```
    /// use ratatui::{
    ///     prelude::*,
    ///     widgets::{TabbedBlock::*, *},
    /// };
    ///
    /// TabbedBlock::default()
    ///     // This tab won't be aligned in the center
    ///     .tab(tab::from("right").alignment(Alignment::Right))
    ///     .tab("foo")
    ///     .tab("bar")
    ///     .tab_alignment(Alignment::Center);
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub const fn tab_alignment(mut self, alignment: Alignment) -> TabbedBlock<'a> {
        self.tabs_alignment = alignment;
        self
    }

    /// Sets the default [`Position`] for all TabbedBlock [tabs](tab).
    ///
    /// tabs that explicitly set a [`Position`] will ignore this.
    ///
    /// # Example
    ///
    /// This example positions all tabs on the bottom except the "top" tab which explicitly sets
    /// [`Position::Top`].
    /// ```
    /// use ratatui::{
    ///     prelude::*,
    ///     widgets::{TabbedBlock::*, *},
    /// };
    ///
    /// TabbedBlock::default()
    ///     // This tab won't be aligned in the center
    ///     .tab(tab::from("top").position(Position::Top))
    ///     .tab("foo")
    ///     .tab("bar")
    ///     .tab_position(Position::Bottom);
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub const fn tab_position(mut self, position: Position) -> TabbedBlock<'a> {
        self.tabs_position = position;
        self
    }

    /// Defines the style of the borders.
    ///
    /// If a [`TabbedBlock::style`] is defined, `border_style` will be applied on top of it.
    ///
    /// # Example
    ///
    /// This example shows a `TabbedBlock` with blue borders.
    /// ```
    /// # use ratatui::{prelude::*, widgets::*};
    /// TabbedBlock::default()
    ///     .borders(Borders::ALL)
    ///     .border_style(Style::new().blue());
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub const fn border_style(mut self, style: Style) -> TabbedBlock<'a> {
        self.border_style = style;
        self
    }

    /// Defines the TabbedBlock style.
    ///
    /// This is the most generic [`Style`] a TabbedBlock can receive, it will be merged with any other
    /// more specific style. Elements can be styled further with [`TabbedBlock::tab_style`] and
    /// [`TabbedBlock::border_style`].
    ///
    /// This will also apply to the widget inside that TabbedBlock, unless the inner widget is styled.
    #[must_use = "method moves the value of self and returns the modified value"]
    pub const fn style(mut self, style: Style) -> TabbedBlock<'a> {
        self.style = style;
        self
    }

    /// Defines which borders to display.
    ///
    /// [`Borders`] can also be styled with [`TabbedBlock::border_style`] and [`TabbedBlock::border_type`].
    ///
    /// # Examples
    ///
    /// Simply show all borders.
    /// ```
    /// # use ratatui::{prelude::*, widgets::*};
    /// TabbedBlock::default().borders(Borders::ALL);
    /// ```
    ///
    /// Display left and right borders.
    /// ```
    /// # use ratatui::{prelude::*, widgets::*};
    /// TabbedBlock::default().borders(Borders::LEFT | Borders::RIGHT);
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub const fn borders(mut self, flag: Borders) -> TabbedBlock<'a> {
        self.borders = flag;
        self
    }

    /// Sets the symbols used to display the border (e.g. single line, double line, thick or
    /// rounded borders).
    ///
    /// Setting this overwrites any custom [`border_set`](TabbedBlock::border_set) that was set.
    ///
    /// See [`BorderType`] for the full list of available symbols.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ratatui::{prelude::*, widgets::*};
    /// TabbedBlock::default()
    ///     .tab("TabbedBlock")
    ///     .borders(Borders::ALL)
    ///     .border_type(BorderType::Rounded);
    /// // Renders
    /// // ╭TabbedBlock╮
    /// // │           │
    /// // ╰───────────╯
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub const fn border_type(mut self, border_type: BorderType) -> TabbedBlock<'a> {
        self.border_set = border_type.to_border_set();
        self
    }

    /// Sets the symbols used to display the border as a [`crate::symbols::border::Set`].
    ///
    /// Setting this overwrites any [`border_type`](TabbedBlock::border_type) that was set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ratatui::{prelude::*, widgets::*};
    /// TabbedBlock::default().tab("TabbedBlock").borders(Borders::ALL).border_set(symbols::border::DOUBLE);
    /// // Renders
    /// // ╔TabbedBlock╗
    /// // ║           ║
    /// // ╚═══════════╝
    #[must_use = "method moves the value of self and returns the modified value"]
    pub const fn border_set(mut self, border_set: line::Set) -> TabbedBlock<'a> {
        self.border_set = border_set;
        self
    }

    /// Compute the inner area of a TabbedBlock based on its border visibility rules.
    ///
    /// # Examples
    ///
    /// Draw a TabbedBlock nested within another TabbedBlock
    /// ```
    /// # use ratatui::{prelude::*, widgets::*};
    /// # fn render_nested_TabbedBlock(frame: &mut Frame) {
    /// let outer_TabbedBlock = TabbedBlock::default().tab("Outer").borders(Borders::ALL);
    /// let inner_TabbedBlock = TabbedBlock::default().tab("Inner").borders(Borders::ALL);
    ///
    /// let outer_area = frame.size();
    /// let inner_area = outer_TabbedBlock.inner(outer_area);
    ///
    /// frame.render_widget(outer_TabbedBlock, outer_area);
    /// frame.render_widget(inner_TabbedBlock, inner_area);
    /// # }
    /// // Renders
    /// // ┌Outer────────┐
    /// // │┌Inner──────┐│
    /// // ││           ││
    /// // │└───────────┘│
    /// // └─────────────┘
    /// ```
    pub fn inner(&self, area: Rect) -> Rect {
        let mut inner = area;
        if self.borders.intersects(Borders::LEFT) {
            inner.x = inner.x.saturating_add(1).min(inner.right());
            inner.width = inner.width.saturating_sub(1);
        }
        if self.borders.intersects(Borders::TOP) && !self.have_tab_at_position(Position::Top) {
            inner.y = inner.y.saturating_add(1).min(inner.bottom());
            inner.height = inner.height.saturating_sub(1);
        }
        if self.borders.intersects(Borders::RIGHT) {
            inner.width = inner.width.saturating_sub(1);
        }
        if self.borders.intersects(Borders::BOTTOM) && !self.have_tab_at_position(Position::Bottom)
        {
            inner.height = inner.height.saturating_sub(1);
        }

        // Calculate for tabs too!
        if self.have_tab_at_position(Position::Top) {
            match self.tabs_type {
                TabType::Full => {
                    inner.y = inner.y.saturating_add(3);
                    inner.height = inner.height.saturating_sub(3);
                }
                TabType::Concise => {
                    inner.y = inner.y.saturating_add(2);
                    inner.height = inner.height.saturating_sub(2);
                }
            }
        }

        if self.have_tab_at_position(Position::Bottom) {
            match self.tabs_type {
                TabType::Full => {
                    inner.height = inner.height.saturating_sub(3);
                }
                TabType::Concise => {
                    inner.height = inner.height.saturating_sub(2);
                }
            }
        }

        inner.x = inner.x.saturating_add(self.padding.left);
        inner.y = inner.y.saturating_add(self.padding.top);

        inner.width = inner
            .width
            .saturating_sub(self.padding.left + self.padding.right);
        inner.height = inner
            .height
            .saturating_sub(self.padding.top + self.padding.bottom);

        inner
    }

    fn have_tab_at_position(&self, position: Position) -> bool {
        self.tabs
            .iter()
            .any(|tab| tab.position.unwrap_or(self.tabs_position) == position)
    }

    /// Defines the padding inside a `TabbedBlock`.
    ///
    /// See [`Padding`] for more information.
    ///
    /// # Examples
    ///
    /// This renders a `TabbedBlock` with no padding (the default).
    /// ```
    /// # use ratatui::{prelude::*, widgets::*};
    /// TabbedBlock::default()
    ///     .borders(Borders::ALL)
    ///     .padding(Padding::zero());
    /// // Renders
    /// // ┌───────┐
    /// // │content│
    /// // └───────┘
    /// ```
    ///
    /// This example shows a `TabbedBlock` with padding left and right ([`Padding::horizontal`]).
    /// Notice the two spaces before and after the content.
    /// ```
    /// # use ratatui::{prelude::*, widgets::*};
    /// TabbedBlock::default()
    ///     .borders(Borders::ALL)
    ///     .padding(Padding::horizontal(2));
    /// // Renders
    /// // ┌───────────┐
    /// // │  content  │
    /// // └───────────┘
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub const fn padding(mut self, padding: Padding) -> TabbedBlock<'a> {
        self.padding = padding;
        self
    }

    fn render_borders(&self, area: Rect, buf: &mut Buffer) {
        buf.set_style(area, self.style);
        let symbols = self.border_set;

        let mut top_border = area.top();
        let mut bottom_border = area.bottom();

        if !self.tabs.is_empty() {
            match self.tabs_type {
                TabType::Full => match self.tabs_position {
                    Position::Top => top_border = area.top() + 2,
                    Position::Bottom => bottom_border = area.bottom() - 2,
                },
                TabType::Concise => match self.tabs_position {
                    Position::Top => top_border = area.top() + 1,
                    Position::Bottom => bottom_border = area.bottom() - 1,
                },
            }
        }

        // Sides
        if self.borders.intersects(Borders::LEFT) {
            for y in top_border..bottom_border {
                buf.get_mut(area.left(), y)
                    .set_symbol(symbols.vertical)
                    .set_style(self.border_style);
            }
        }
        if self.borders.intersects(Borders::TOP) || self.have_tab_at_position(Position::Top) {
            for x in area.left()..area.right() {
                buf.get_mut(x, top_border)
                    .set_symbol(symbols.horizontal)
                    .set_style(self.border_style);
            }
        }
        if self.borders.intersects(Borders::RIGHT) {
            let x = area.right() - 1;
            for y in top_border..bottom_border {
                buf.get_mut(x, y)
                    .set_symbol(symbols.vertical)
                    .set_style(self.border_style);
            }
        }
        if self.borders.intersects(Borders::BOTTOM) || self.have_tab_at_position(Position::Bottom) {
            let y = bottom_border - 1;
            for x in area.left()..area.right() {
                buf.get_mut(x, y)
                    .set_symbol(symbols.horizontal)
                    .set_style(self.border_style);
            }
        }

        // Corners
        if self.borders.contains(Borders::RIGHT | Borders::BOTTOM) {
            buf.get_mut(area.right() - 1, bottom_border - 1)
                .set_symbol(symbols.bottom_right)
                .set_style(self.border_style);
        }
        if self.borders.contains(Borders::RIGHT | Borders::TOP) {
            buf.get_mut(area.right() - 1, top_border)
                .set_symbol(symbols.top_right)
                .set_style(self.border_style);
        }
        if self.borders.contains(Borders::LEFT | Borders::BOTTOM) {
            buf.get_mut(area.left(), bottom_border - 1)
                .set_symbol(symbols.bottom_left)
                .set_style(self.border_style);
        }
        if self.borders.contains(Borders::LEFT | Borders::TOP) {
            buf.get_mut(area.left(), top_border)
                .set_symbol(symbols.top_left)
                .set_style(self.border_style);
        }
    }

    /* tabs Rendering */
    fn get_tab_y(&self, position: Position, area: Rect) -> u16 {
        match self.tabs_type {
            TabType::Full => match position {
                Position::Bottom => area.bottom() - 2,
                Position::Top => area.top() + 1,
            },
            TabType::Concise => match position {
                Position::Bottom => area.bottom() - 1,
                Position::Top => area.top(),
            },
        }
    }

    fn tab_filter(&self, tab: &Tab, alignment: Alignment, position: Position) -> bool {
        tab.alignment.unwrap_or(self.tabs_alignment) == alignment
            && tab.position.unwrap_or(self.tabs_position) == position
    }

    fn calculate_tab_area_offsets(&self, area: Rect) -> (u16, u16, u16) {
        let left_border_dx = u16::from(self.borders.intersects(Borders::LEFT));
        let right_border_dx = u16::from(self.borders.intersects(Borders::RIGHT));

        let tab_area_width = area
            .width
            .saturating_sub(left_border_dx)
            .saturating_sub(right_border_dx);

        (left_border_dx, right_border_dx, tab_area_width)
    }

    fn render_left_tabs(&self, position: Position, area: Rect, buf: &mut Buffer) {
        let (left_border_dx, _, _) = self.calculate_tab_area_offsets(area);
        let mut current_offset = left_border_dx;
        self.tabs
            .iter()
            .filter(|tab| self.tab_filter(tab, Alignment::Left, position))
            .for_each(|tab| {
                let tab_x = current_offset;
                current_offset += tab.content.width() as u16 + 4 + 1;

                // Clone the tab's content, applying TabbedBlock tab style then the tab style
                let mut content = tab.content.clone();
                for span in content.spans.iter_mut() {
                    span.style = self.tabs_style.patch(span.style);
                }

                let tab_width = content.width() as u16 + 3;
                let tab_height = if self.tabs_type == TabType::Full {
                    3
                } else {
                    2
                };
                let left_edge = tab_x + area.left();

                let top_line = self.get_tab_y(position, area) - 1;

                let rect: Rect = Rect {
                    x: left_edge,
                    y: top_line,
                    width: tab_width,
                    height: tab_height,
                };
                Clear.render(rect, buf);

                match self.tabs_type {
                    TabType::Full => match position {
                        Position::Top => self.draw_top_full_tab(
                            rect,
                            self.current_tab == tab.index,
                            &content,
                            buf,
                        ),
                        Position::Bottom => self.draw_bottom_full_tab(
                            rect,
                            self.current_tab == tab.index,
                            &content,
                            buf,
                        ),
                    },
                    TabType::Concise => match position {
                        Position::Top => self.draw_top_concise_tab(
                            rect,
                            self.current_tab == tab.index,
                            &content,
                            buf,
                        ),
                        Position::Bottom => self.draw_bottom_concise_tab(
                            rect,
                            self.current_tab == tab.index,
                            &content,
                            buf,
                        ),
                    },
                }
            });
    }

    fn render_center_tabs(&self, position: Position, area: Rect, buf: &mut Buffer) {
        let tabs = self
            .tabs
            .iter()
            .filter(|tab| self.tab_filter(tab, Alignment::Center, position));

        let tabs_sum = tabs.clone().fold(-1, |acc, f: &Tab<'_>| {
            acc + f.content.width() as i16 + 1 + 4
        }); // First element isn't spaced

        let mut current_offset = area.width.saturating_sub(tabs_sum as u16) / 2;
        tabs.for_each(|tab| {
            let tab_x = current_offset;
            current_offset += tab.content.width() as u16 + 1 + 4;

            // Clone the tab's content, applying TabbedBlock tab style then the tab style
            let mut content = tab.content.clone();
            for span in content.spans.iter_mut() {
                span.style = self.tabs_style.patch(span.style);
            }

            let tab_width = content.width() as u16 + 3;
            let tab_height = if self.tabs_type == TabType::Full {
                3
            } else {
                2
            };

            let left_edge = tab_x + area.left();

            let top_line = self.get_tab_y(position, area) - 1;

            let rect: Rect = Rect {
                x: left_edge,
                y: top_line,
                width: tab_width,
                height: tab_height,
            };
            Clear.render(rect, buf);

            match self.tabs_type {
                TabType::Full => match position {
                    Position::Top => {
                        self.draw_top_full_tab(rect, self.current_tab == tab.index, &content, buf)
                    }
                    Position::Bottom => self.draw_bottom_full_tab(
                        rect,
                        self.current_tab == tab.index,
                        &content,
                        buf,
                    ),
                },
                TabType::Concise => match position {
                    Position::Top => self.draw_top_concise_tab(
                        rect,
                        self.current_tab == tab.index,
                        &content,
                        buf,
                    ),
                    Position::Bottom => self.draw_bottom_concise_tab(
                        rect,
                        self.current_tab == tab.index,
                        &content,
                        buf,
                    ),
                },
            }
        });
    }

    fn render_right_tabs(&self, position: Position, area: Rect, buf: &mut Buffer) {
        let (_, right_border_dx, _) = self.calculate_tab_area_offsets(area);

        let mut current_offset = right_border_dx;
        self.tabs
            .iter()
            .filter(|tab| self.tab_filter(tab, Alignment::Right, position))
            .rev() // so that the tabs appear in the order they have been set
            .for_each(|tab| {
                current_offset += tab.content.width() as u16 + 4 + 1;
                let tab_x = current_offset - 1; // First element isn't spaced

                // Clone the tab's content, applying TabbedBlock tab style then the tab style
                let mut content = tab.content.clone();
                for span in content.spans.iter_mut() {
                    span.style = self.tabs_style.patch(span.style);
                }

                let tab_width = content.width() as u16 + 3;
                let tab_height = if self.tabs_type == TabType::Full {
                    3
                } else {
                    2
                };

                let left_edge = area.width.saturating_sub(tab_x) + area.left();
                let top_line = self.get_tab_y(position, area) - 1;

                let rect: Rect = Rect {
                    x: left_edge,
                    y: top_line,
                    width: tab_width,
                    height: tab_height + 1,
                };
                Clear.render(rect, buf);

                match self.tabs_type {
                    TabType::Full => match position {
                        Position::Top => self.draw_top_full_tab(
                            rect,
                            self.current_tab == tab.index,
                            &content,
                            buf,
                        ),
                        Position::Bottom => self.draw_bottom_full_tab(
                            rect,
                            self.current_tab == tab.index,
                            &content,
                            buf,
                        ),
                    },
                    TabType::Concise => match position {
                        Position::Top => self.draw_top_concise_tab(
                            rect,
                            self.current_tab == tab.index,
                            &content,
                            buf,
                        ),
                        Position::Bottom => self.draw_bottom_concise_tab(
                            rect,
                            self.current_tab == tab.index,
                            &content,
                            buf,
                        ),
                    },
                }
            });
    }

    fn draw_bottom_full_tab(
        &self,
        area: Rect,
        selected: bool,
        content: &Line<'_>,
        buf: &mut Buffer,
    ) {
        let symbols = self.border_set;

        let left_edge = area.x;
        let right_edge = left_edge + area.width;

        let top_line = area.y;
        let middle_line = area.y + 1;
        let bottom_line = area.y + 2;

        // Middle Line
        buf.set_line(left_edge + 2, middle_line, content, content.width() as u16);
        // Line edges
        buf.get_mut(left_edge, middle_line)
            .set_symbol(symbols.vertical)
            .set_style(self.border_style);
        buf.get_mut(right_edge, middle_line)
            .set_symbol(symbols.vertical)
            .set_style(self.border_style);

        /* for x in left_edge + 1..right_edge {
            buf.get_mut(x, middle_line).reset();
        } */

        if selected {
            buf.get_mut(left_edge, top_line)
                .set_symbol(symbols.top_right)
                .set_style(self.border_style);
            buf.get_mut(right_edge, top_line)
                .set_symbol(symbols.top_left)
                .set_style(self.border_style);
            for x in left_edge + 1..right_edge {
                buf.get_mut(x, top_line).reset();
            }
        } else {
            // Set top corners
            buf.get_mut(left_edge, top_line)
                .set_symbol(symbols.horizontal_down)
                .set_style(self.border_style);
            buf.get_mut(right_edge, top_line)
                .set_symbol(symbols.horizontal_down)
                .set_style(self.border_style);
            // Set top of content
            for x in left_edge + 1..right_edge {
                buf.get_mut(x, top_line)
                    .set_symbol(symbols.horizontal)
                    .set_style(self.border_style);
            }
        }
        // Set bottom of content
        for x in left_edge + 1..right_edge {
            buf.get_mut(x, bottom_line)
                .set_symbol(symbols.horizontal)
                .set_style(self.border_style);
        }

        // Set Bottom Corners
        buf.get_mut(left_edge, bottom_line)
            .set_symbol(symbols.bottom_left)
            .set_style(self.border_style);
        buf.get_mut(right_edge, bottom_line)
            .set_symbol(symbols.bottom_right)
            .set_style(self.border_style);
    }

    fn draw_top_full_tab(&self, area: Rect, selected: bool, content: &Line<'_>, buf: &mut Buffer) {
        let symbols = self.border_set;

        let left_edge = area.x;
        let right_edge = left_edge + area.width;

        let top_line = area.y;
        let middle_line = area.y + 1;
        let bottom_line = area.y + 2;

        // Middle Line
        buf.set_line(left_edge + 2, middle_line, content, content.width() as u16);
        // Line edges
        buf.get_mut(left_edge, middle_line)
            .set_symbol(symbols.vertical)
            .set_style(self.border_style);
        buf.get_mut(right_edge, middle_line)
            .set_symbol(symbols.vertical)
            .set_style(self.border_style);

        // Set top of content
        for x in left_edge..right_edge {
            buf.get_mut(x, top_line)
                .set_symbol(symbols.horizontal)
                .set_style(self.border_style);
        }

        // Set Top Corners
        buf.get_mut(left_edge, top_line)
            .set_symbol(symbols.top_left)
            .set_style(self.border_style);
        buf.get_mut(right_edge, top_line)
            .set_symbol(symbols.top_right)
            .set_style(self.border_style);

        /* // reset
        for x in left_edge + 1..right_edge {
            buf.get_mut(x, middle_line).reset();
        } */

        if selected {
            // Set Bottom Corners
            buf.get_mut(left_edge, bottom_line)
                .set_symbol(symbols.bottom_right)
                .set_style(self.border_style);
            buf.get_mut(right_edge, bottom_line)
                .set_symbol(symbols.bottom_left)
                .set_style(self.border_style); // Set bottom of content
            for x in left_edge + 1..right_edge {
                buf.get_mut(x, bottom_line).reset();
            }
        } else {
            // Set bottom corners
            buf.get_mut(left_edge, bottom_line)
                .set_symbol(symbols.horizontal_up)
                .set_style(self.border_style);
            buf.get_mut(right_edge, bottom_line)
                .set_symbol(symbols.horizontal_up)
                .set_style(self.border_style);

            // Set bottom of content
            for x in left_edge + 1..right_edge {
                buf.get_mut(x, bottom_line)
                    .set_symbol(symbols.horizontal)
                    .set_style(self.border_style);
            }
        }
    }

    fn draw_top_concise_tab(
        &self,
        area: Rect,
        selected: bool,
        content: &Line<'_>,
        buf: &mut Buffer,
    ) {
        let symbols = self.border_set;

        let left_edge = area.x;
        let right_edge = left_edge + area.width;

        let middle_line = area.y + 1;
        let bottom_line = area.y + 2;

        // Middle Line
        buf.set_line(left_edge + 2, middle_line, content, content.width() as u16);

        // Line edges
        buf.get_mut(left_edge, middle_line)
            .set_symbol(symbols.top_left)
            .set_style(self.border_style);
        buf.get_mut(right_edge, middle_line)
            .set_symbol(symbols.top_right)
            .set_style(self.border_style);

        /* for x in left_edge + 1..right_edge {
            buf.get_mut(x, middle_line).reset();
        } */

        /* // If selected add the frames
        if selected {
            buf.get_mut(left_edge + 1, middle_line)
                .set_symbol(symbols.vertical_left)
                .set_style(self.border_style);
            buf.get_mut(right_edge - 1, middle_line)
                .set_symbol(symbols.vertical_right)
                .set_style(self.border_style);
        } */

        if selected {
            // Set Bottom Corners
            buf.get_mut(left_edge, bottom_line)
                .set_symbol(symbols.bottom_right)
                .set_style(self.border_style);
            buf.get_mut(right_edge, bottom_line)
                .set_symbol(symbols.bottom_left)
                .set_style(self.border_style);
            for x in left_edge + 1..right_edge {
                buf.get_mut(x, bottom_line).reset();
            }
        } else {
            // Set bottom corners
            buf.get_mut(left_edge, bottom_line)
                .set_symbol(symbols.horizontal_up)
                .set_style(self.border_style);
            buf.get_mut(right_edge, bottom_line)
                .set_symbol(symbols.horizontal_up)
                .set_style(self.border_style);

            // Set bottom of content
            for x in left_edge + 1..right_edge {
                buf.get_mut(x, bottom_line)
                    .set_symbol(symbols.horizontal)
                    .set_style(self.border_style);
            }
        }
    }

    fn draw_bottom_concise_tab(
        &self,
        area: Rect,
        selected: bool,
        content: &Line<'_>,
        buf: &mut Buffer,
    ) {
        let symbols = self.border_set;

        let left_edge = area.x;
        let right_edge = left_edge + area.width;

        let top_line = area.y;
        let middle_line = area.y + 1;

        // Middle Line
        buf.set_line(left_edge + 2, middle_line, content, content.width() as u16);
        // Line edges
        buf.get_mut(left_edge, middle_line)
            .set_symbol(symbols.bottom_left)
            .set_style(self.border_style);
        buf.get_mut(right_edge, middle_line)
            .set_symbol(symbols.bottom_right)
            .set_style(self.border_style);

        /* for x in left_edge + 1..right_edge {
            buf.get_mut(x, middle_line).reset();
        } */

        // Frames
        /* if selected {
            buf.get_mut(left_edge + 1, middle_line)
                .set_symbol(symbols.vertical_left)
                .set_style(self.border_style);
            buf.get_mut(right_edge - 1, middle_line)
                .set_symbol(symbols.vertical_right)
                .set_style(self.border_style);
        } */

        if selected {
            buf.get_mut(left_edge, top_line)
                .set_symbol(symbols.top_right)
                .set_style(self.border_style);
            buf.get_mut(right_edge, top_line)
                .set_symbol(symbols.top_left)
                .set_style(self.border_style);
            for x in left_edge + 1..right_edge {
                buf.get_mut(x, top_line).reset();
            }
        } else {
            // Set top corners
            buf.get_mut(left_edge, top_line)
                .set_symbol(symbols.horizontal_down)
                .set_style(self.border_style);
            buf.get_mut(right_edge, top_line)
                .set_symbol(symbols.horizontal_down)
                .set_style(self.border_style);
            // Set top of content
            for x in left_edge + 1..right_edge {
                buf.get_mut(x, top_line)
                    .set_symbol(symbols.horizontal)
                    .set_style(self.border_style);
            }
        }
    }

    fn render_tab_position(&self, position: Position, area: Rect, buf: &mut Buffer) {
        // Note: the order in which these functions are called define the overlapping behavior
        self.render_right_tabs(position, area, buf);
        self.render_center_tabs(position, area, buf);
        self.render_left_tabs(position, area, buf);
    }

    fn render_tabs(&self, area: Rect, buf: &mut Buffer) {
        self.render_tab_position(Position::Top, area, buf);
        self.render_tab_position(Position::Bottom, area, buf);
    }
}

impl<'a> Widget for TabbedBlock<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.area() == 0 {
            return;
        }
        self.render_borders(area, buf);
        self.render_tabs(area, buf);
        for x in (area.x)..(area.x + area.width) {
            for y in (area.y)..(area.y + area.height) {
                buf.get_mut(x, y).set_style(Style::new());
            }
        }
    }
}

impl<'a> Styled for TabbedBlock<'a> {
    type Item = TabbedBlock<'a>;

    fn style(&self) -> Style {
        self.style
    }

    fn set_style(self, style: Style) -> Self::Item {
        self.style(style)
    }
}
