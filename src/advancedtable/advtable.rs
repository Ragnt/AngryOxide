#![warn(missing_docs)]
#![allow(unexpected_cfgs)]
use std::iter;

use itertools::Itertools;
use ratatui::{layout::Constraint, style::Style, text::Text};
use strum::{Display, EnumString};
use unicode_width::UnicodeWidthStr;

use ratatui::{
    layout::SegmentSize,
    prelude::*,
    widgets::{Block, StatefulWidget, TableState, Widget},
};

/// A widget to display data in formatted columns.
///
/// A `Table` is a collection of [`Row`]s, each composed of [`Cell`]s:
///
/// You can consutrct a [`Table`] using either [`Table::new`] or [`Table::default`] and then chain
/// builder style methods to set the desired properties.
///
/// Make sure to call the [`Table::widths`] method, otherwise the columns will all have a width of 0
/// and thus not be visible.
///
/// [`Table`] implements [`Widget`] and so it can be drawn using [`Frame::render_widget`].
///
/// [`Table`] is also a [`StatefulWidget`], which means you can use it with [`TableState`] to allow
/// the user to scroll through the rows and select one of them.
///
/// See the [table example] and the recipe and traceroute tabs in the [demo2 example] for a more in
/// depth example of the various configuration options and for how to handle state.
///
/// [table example]: https://github.com/ratatui-org/ratatui/blob/master/examples/table.rs
/// [demo2 example]: https://github.com/ratatui-org/ratatui/blob/master/examples/demo2/
///
/// # Constructor methods
///
/// - [`Table::new`] creates a new [`Table`] with the given rows.
/// - [`Table::default`] creates an empty [`Table`]. You can then add rows using [`Table::rows`].
///
/// # Setter methods
///
/// These methods a fluent setters. They return a new `Table` with the specified property set.
///
/// - [`Table::rows`] sets the rows of the [`Table`].
/// - [`Table::header`] sets the header row of the [`Table`].
/// - [`Table::widths`] sets the width constraints of each column.
/// - [`Table::column_spacing`] sets the spacing between each column.
/// - [`Table::block`] wraps the table in a [`Block`] widget.
/// - [`Table::style`] sets the base style of the widget.
/// - [`Table::highlight_style`] sets the style of the selected row.
/// - [`Table::highlight_symbol`] sets the symbol to be displayed in front of the selected row.
/// - [`Table::highlight_spacing`] sets when to show the highlight spacing.
///
/// # Example
///
/// ```rust
/// use ratatui::{prelude::*, widgets::*};
///
/// let rows = [Row::new(vec!["Cell1", "Cell2", "Cell3"])];
/// // Columns widths are constrained in the same way as Layout...
/// let widths = [
///     Constraint::Length(5),
///     Constraint::Length(5),
///     Constraint::Length(10),
/// ];
/// let table = Table::new(rows, widths)
///     // ...and they can be separated by a fixed spacing.
///     .column_spacing(1)
///     // You can set the style of the entire Table.
///     .style(Style::new().blue())
///     // It has an optional header, which is simply a Row always visible at the top.
///     .header(
///         Row::new(vec!["Col1", "Col2", "Col3"])
///             .style(Style::new().bold())
///             // To add space between the header and the rest of the rows, specify the margin
///             .bottom_margin(1),
///     )
///     // As any other widget, a Table can be wrapped in a Block.
///     .block(Block::default().title("Table"))
///     // The selected row and its content can also be styled.
///     .highlight_style(Style::new().reversed())
///     // ...and potentially show a symbol in front of the selection.
///     .highlight_symbol(">>");
/// ```
///
/// Rows can be created from an iterator of [`Cell`]s. Each row can have an associated height,
/// bottom margin, and style. See [`Row`] for more details.
///
/// ```rust
/// # use ratatui::{prelude::*, widgets::*};
/// // a Row can be created from simple strings.
/// let row = Row::new(vec!["Row11", "Row12", "Row13"]);
///
/// // You can style the entire row.
/// let row = Row::new(vec!["Row21", "Row22", "Row23"]).style(Style::new().red());
///
/// // If you need more control over the styling, create Cells directly
/// let row = Row::new(vec![
///     Cell::from("Row31"),
///     Cell::from("Row32").style(Style::default().fg(Color::Yellow)),
///     Cell::from(Line::from(vec![
///         Span::raw("Row"),
///         Span::styled("33", Style::default().fg(Color::Green)),
///     ])),
/// ]);
///
/// // If a Row need to display some content over multiple lines, specify the height.
/// let row = Row::new(vec![
///     Cell::from("Row\n41"),
///     Cell::from("Row\n42"),
///     Cell::from("Row\n43"),
/// ])
/// .height(2);
/// ```
///
/// Cells can be created from anything that can be converted to [`Text`]. See [`Cell`] for more
/// details.
///
/// ```rust
/// # use ratatui::{prelude::*, widgets::*};
/// Cell::from("simple string");
/// Cell::from("simple styled span".red());
/// Cell::from(Span::raw("raw span"));
/// Cell::from(Span::styled("styled span", Style::new().red()));
/// Cell::from(Line::from(vec![
///     Span::raw("a vec of "),
///     Span::styled("spans", Style::new().bold()),
/// ]));
/// Cell::from(Text::from("text"));
/// ```
///
/// `Table` also implements the [`Styled`] trait, which means you can use style shorthands from
/// the [`Stylize`] trait to set the style of the widget more concisely.
///
/// ```rust
/// use ratatui::{prelude::*, widgets::*};
///
/// let rows = [Row::new(vec!["Cell1", "Cell2", "Cell3"])];
/// let widths = [
///     Constraint::Length(5),
///     Constraint::Length(5),
///     Constraint::Length(10),
/// ];
/// let table = Table::new(rows, widths).red().italic();
/// ```
///
/// # Stateful example
///
/// `Table` is a [`StatefulWidget`], which means you can use it with [`TableState`] to allow the
/// user to scroll through the rows and select one of them.
///
/// ```rust
/// # use ratatui::{prelude::*, widgets::*};
/// # fn ui(frame: &mut Frame) {
/// # let area = Rect::default();
/// // Note: TableState should be stored in your application state (not constructed in your render
/// // method) so that the selected row is preserved across renders
/// let mut table_state = TableState::default();
/// let rows = [
///     Row::new(vec!["Row11", "Row12", "Row13"]),
///     Row::new(vec!["Row21", "Row22", "Row23"]),
///     Row::new(vec!["Row31", "Row32", "Row33"]),
/// ];
/// let widths = [Constraint::Length(5), Constraint::Length(5), Constraint::Length(10)];
/// let table = Table::new(rows, widths)
///     .block(Block::default().title("Table"))
///     .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
///     .highlight_symbol(">>");
///
/// frame.render_stateful_widget(table, area, &mut table_state);
/// # }
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct AdvTable<'a> {
    /// Data to display in each row
    rows: Vec<Row<'a>>,

    /// Optional header
    header: Option<Row<'a>>,

    /// Width constraints for each column
    widths: Vec<Constraint>,

    /// Space between each column
    column_spacing: u16,

    /// A block to wrap the widget in
    block: Option<Block<'a>>,

    /// Base style for the widget
    style: Style,

    /// Style used to render the selected row
    highlight_style: Style,

    /// Symbol in front of the selected rom
    highlight_symbol: Option<&'a str>,

    /// Decides when to allocate spacing for the row selection
    highlight_spacing: HighlightSpacing,

    /// Controls how to distribute extra space among the columns
    segment_size: SegmentSize,

    /// The area of the table.
    area: Rect,

    /// The area of the selected row.
    selected_row_area: Option<Rect>,
}

/// A single row of data to be displayed in a [`Table`] widget.
///
/// A `Row` is a collection of [`Cell`]s.
///
/// By default, a row has a height of 1 but you can change this using [`Row::height`].
///
/// You can set the style of the entire row using [`Row::style`]. This [`Style`] will be combined
/// with the [`Style`] of each individual [`Cell`] by adding the [`Style`] of the [`Cell`] to the
/// [`Style`] of the [`Row`].
///
/// # Examples
///
/// You can create `Row`s from simple strings.
///
/// ```rust
/// use ratatui::{prelude::*, widgets::*};
///
/// Row::new(vec!["Cell1", "Cell2", "Cell3"]);
/// ```
///
/// If you need a bit more control over individual cells, you can explicitly create [`Cell`]s:
///
/// ```rust
/// use ratatui::{prelude::*, widgets::*};
///
/// Row::new(vec![
///     Cell::from("Cell1"),
///     Cell::from("Cell2").style(Style::default().fg(Color::Yellow)),
/// ]);
/// ```
///
/// You can also construct a row from any type that can be converted into [`Text`]:
///
/// ```rust
/// use std::borrow::Cow;
///
/// use ratatui::{prelude::*, widgets::*};
///
/// Row::new(vec![
///     Cow::Borrowed("hello"),
///     Cow::Owned("world".to_uppercase()),
/// ]);
/// ```
///
/// `Row` implements [`Styled`] which means you can use style shorthands from the [`Stylize`] trait
/// to set the style of the row concisely.
///
/// ```rust
/// use ratatui::{prelude::*, widgets::*};
/// let cells = vec!["Cell1", "Cell2", "Cell3"];
/// Row::new(cells).red().italic();
/// ```
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct Row<'a> {
    cells: Vec<Cell<'a>>,
    height: u16,
    bottom_margin: u16,
    style: Style,
}

/// A [`Cell`] contains the [`Text`] to be displayed in a [`Row`] of a [`Table`].
///
/// You can apply a [`Style`] to the [`Cell`] using [`Cell::style`]. This will set the style for the
/// entire area of the cell. Any [`Style`] set on the [`Text`] content will be combined with the
/// [`Style`] of the [`Cell`] by adding the [`Style`] of the [`Text`] content to the [`Style`] of
/// the [`Cell`]. Styles set on the text content will only affect the content.
///
/// # Examples
///
/// You can create a `Cell` from anything that can be converted to a [`Text`].
///
/// ```rust
/// use std::borrow::Cow;
///
/// use ratatui::{prelude::*, widgets::*};
///
/// Cell::from("simple string");
/// Cell::from(Span::from("span"));
/// Cell::from(Line::from(vec![
///     Span::raw("a vec of "),
///     Span::styled("spans", Style::default().add_modifier(Modifier::BOLD)),
/// ]));
/// Cell::from(Text::from("a text"));
/// Cell::from(Text::from(Cow::Borrowed("hello")));
/// ```
///
/// `Cell` implements [`Styled`] which means you can use style shorthands from the [`Stylize`] trait
/// to set the style of the cell concisely.
///
/// ```rust
/// use ratatui::{prelude::*, widgets::*};
/// Cell::new("Cell 1").red().italic();
/// ```
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub struct Cell<'a> {
    content: Text<'a>,
    style: Style,
}

/// This option allows the user to configure the "highlight symbol" column width spacing
#[derive(Debug, Display, EnumString, PartialEq, Eq, Clone, Default, Hash)]
pub enum HighlightSpacing {
    /// Always add spacing for the selection symbol column
    ///
    /// With this variant, the column for the selection symbol will always be allocated, and so the
    /// table will never change size, regardless of if a row is selected or not
    Always,

    /// Only add spacing for the selection symbol column if a row is selected
    ///
    /// With this variant, the column for the selection symbol will only be allocated if there is a
    /// selection, causing the table to shift if selected / unselected
    #[default]
    WhenSelected,

    /// Never add spacing to the selection symbol column, regardless of whether something is
    /// selected or not
    ///
    /// This means that the highlight symbol will never be drawn
    Never,
}

/// State of a [`Table`] widget
///
/// This state can be used to scroll through the rows and select one of them. When the table is
/// rendered as a stateful widget, the selected row will be highlighted and the table will be
/// shifted to ensure that the selected row is visible. This will modify the [`TableState`] object
/// passed to the [`Frame::render_stateful_widget`] method.
///
/// The state consists of two fields:
/// - [`offset`]: the index of the first row to be displayed
/// - [`selected`]: the index of the selected row, which can be `None` if no row is selected
///
/// [`offset`]: TableState::offset()
/// [`selected`]: TableState::selected()
///
/// See the [table example] and the recipe and traceroute tabs in the [demo2 example] for a more in
/// depth example of the various configuration options and for how to handle state.
///
/// [table example]: https://github.com/ratatui-org/ratatui/blob/master/examples/table.rs
/// [demo2 example]: https://github.com/ratatui-org/ratatui/blob/master/examples/demo2/
///
/// # Example
///
/// ```rust
/// # use ratatui::{prelude::*, widgets::*};
/// # fn ui(frame: &mut Frame) {
/// # let area = Rect::default();
/// # let rows = [Row::new(vec!["Cell1", "Cell2"])];
/// # let widths = [Constraint::Length(5), Constraint::Length(5)];
/// let table = Table::new(rows, widths).widths(widths);
///
/// // Note: TableState should be stored in your application state (not constructed in your render
/// // method) so that the selected row is preserved across renders
/// let mut table_state = TableState::default();
/// *table_state.offset_mut() = 1; // display the second row and onwards
/// table_state.select(Some(3)); // select the forth row (0-indexed)
///
/// frame.render_stateful_widget(table, area, &mut table_state);
/// # }
/// ```
impl<'a> AdvTable<'a> {
    /// Creates a new [`Table`] widget with the given rows.
    ///
    /// The `rows` parameter accepts any value that can be converted into an iterator of [`Row`]s.
    /// This includes arrays, slices, and [`Vec`]s.
    ///
    /// The `widths` parameter is an array (or any other type that implements IntoIterator) of
    /// [`Constraint`]s, this holds the widths of each column. This parameter was added in 0.25.0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// let rows = [
    ///     Row::new(vec!["Cell1", "Cell2"]),
    ///     Row::new(vec!["Cell3", "Cell4"]),
    /// ];
    /// let widths = [Constraint::Length(5), Constraint::Length(5)];
    /// let area = frame.area
    /// let table = Table::new(rows, widths, area);
    /// ```
    pub fn new<R, C>(rows: R, widths: C, area: Rect) -> Self
    where
        R: IntoIterator<Item = Row<'a>>,
        C: IntoIterator,
        C::Item: AsRef<Constraint>,
    {
        let widths = widths.into_iter().map(|c| *c.as_ref()).collect_vec();
        ensure_percentages_less_than_100(&widths);
        Self {
            rows: rows.into_iter().collect(),
            widths,
            column_spacing: 1,
            // Note: None is not the default value for SegmentSize, so we need to explicitly set it
            segment_size: SegmentSize::None,
            area,
            ..Default::default()
        }
    }

    /// Set the rows
    ///
    /// The `rows` parameter accepts any value that can be converted into an iterator of [`Row`]s.
    /// This includes arrays, slices, and [`Vec`]s.
    ///
    /// # Warning
    ///
    /// This method does not currently set the column widths. You will need to set them manually by
    /// calling [`Table::widths`].
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// let rows = [
    ///     Row::new(vec!["Cell1", "Cell2"]),
    ///     Row::new(vec!["Cell3", "Cell4"]),
    /// ];
    /// let table = Table::default().rows(rows);
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn rows<T>(mut self, rows: T) -> Self
    where
        T: IntoIterator<Item = Row<'a>>,
    {
        self.rows = rows.into_iter().collect();
        self
    }

    /// Sets the header row
    ///
    /// The `header` parameter is a [`Row`] which will be displayed at the top of the [`Table`]
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// let header = Row::new(vec![
    ///     Cell::from("Header Cell 1"),
    ///     Cell::from("Header Cell 2"),
    /// ]);
    /// let table = Table::default().header(header);
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn header(mut self, header: Row<'a>) -> Self {
        self.header = Some(header);
        self
    }

    /// Set the widths of the columns
    ///
    /// The `widths` parameter accepts anything which be converted to an Iterator of Constraints
    /// which can be an array, slice, Vec etc.
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// let table = Table::default().widths([Constraint::Length(5), Constraint::Length(5)]);
    /// let table = Table::default().widths(&[Constraint::Length(5), Constraint::Length(5)]);
    ///
    /// // widths could also be computed at runtime
    /// let widths = [10, 10, 20].into_iter().map(|c| Constraint::Length(c));
    /// let table = Table::default().widths(widths);
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn widths<I>(mut self, widths: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<Constraint>,
    {
        let widths = widths.into_iter().map(|c| *c.as_ref()).collect_vec();
        ensure_percentages_less_than_100(&widths);
        self.widths = widths;
        self
    }

    /// Set the spacing between columns
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// # let rows = [Row::new(vec!["Cell1", "Cell2"])];
    /// # let widths = [Constraint::Length(5), Constraint::Length(5)];
    /// let table = Table::new(rows, widths).column_spacing(1);
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn column_spacing(mut self, spacing: u16) -> Self {
        self.column_spacing = spacing;
        self
    }

    /// Wraps the table with a custom [`Block`] widget.
    ///
    /// The `block` parameter is of type [`Block`]. This holds the specified block to be
    /// created around the [`Table`]
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// # let rows = [Row::new(vec!["Cell1", "Cell2"])];
    /// # let widths = [Constraint::Length(5), Constraint::Length(5)];
    /// let block = Block::default().title("Table").borders(Borders::ALL);
    /// let table = Table::new(rows, widths).block(block);
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    /// Sets the base style of the widget
    ///
    /// All text rendered by the widget will use this style, unless overridden by [`Block::style`],
    /// [`Row::style`], [`Cell::style`], or the styles of cell's content.
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// # let rows = [Row::new(vec!["Cell1", "Cell2"])];
    /// # let widths = [Constraint::Length(5), Constraint::Length(5)];
    /// let table = Table::new(rows, widths).style(Style::new().red().italic());
    /// ```
    ///
    /// `Table` also implements the [`Styled`] trait, which means you can use style shorthands from
    /// the [`Stylize`] trait to set the style of the widget more concisely.
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// # let rows = [Row::new(vec!["Cell1", "Cell2"])];
    /// # let widths = vec![Constraint::Length(5), Constraint::Length(5)];
    /// let table = Table::new(rows, widths).red().italic();
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    /// Set the style of the selected row
    ///
    /// This style will be applied to the entire row, including the selection symbol if it is
    /// displayed, and will override any style set on the row or on the individual cells.
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// # let rows = [Row::new(vec!["Cell1", "Cell2"])];
    /// # let widths = [Constraint::Length(5), Constraint::Length(5)];
    /// let table = Table::new(rows, widths).highlight_style(Style::new().red().italic());
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn highlight_style(mut self, highlight_style: Style) -> Self {
        self.highlight_style = highlight_style;
        self
    }

    /// Set the symbol to be displayed in front of the selected row
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// # let rows = [Row::new(vec!["Cell1", "Cell2"])];
    /// # let widths = [Constraint::Length(5), Constraint::Length(5)];
    /// let table = Table::new(rows, widths).highlight_symbol(">>");
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn highlight_symbol(mut self, highlight_symbol: &'a str) -> Self {
        self.highlight_symbol = Some(highlight_symbol);
        self
    }

    /// Set when to show the highlight spacing
    ///
    /// The highlight spacing is the spacing that is allocated for the selection symbol column (if
    /// enabled) and is used to shift the table when a row is selected. This method allows you to
    /// configure when this spacing is allocated.
    ///
    /// - [`HighlightSpacing::Always`] will always allocate the spacing, regardless of whether a row
    ///   is selected or not. This means that the table will never change size, regardless of if a
    ///   row is selected or not.
    /// - [`HighlightSpacing::WhenSelected`] will only allocate the spacing if a row is selected.
    ///   This means that the table will shift when a row is selected. This is the default setting
    ///   for backwards compatibility, but it is recommended to use `HighlightSpacing::Always` for a
    ///   better user experience.
    /// - [`HighlightSpacing::Never`] will never allocate the spacing, regardless of whether a row
    ///   is selected or not. This means that the highlight symbol will never be drawn.
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// # let rows = [Row::new(vec!["Cell1", "Cell2"])];
    /// # let widths = [Constraint::Length(5), Constraint::Length(5)];
    /// let table = Table::new(rows, widths).highlight_spacing(HighlightSpacing::Always);
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn highlight_spacing(mut self, value: HighlightSpacing) -> Self {
        self.highlight_spacing = value;
        self
    }

    /// Set how extra space is distributed amongst columns.
    ///
    /// This determines how the space is distributed when the constraints are satisfied. By default,
    /// the extra space is not distributed at all.  But this can be changed to distribute all extra
    /// space to the last column or to distribute it equally.
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// Create a table that needs at least 30 columns to display.  Any extra space will be assigned
    /// to the last column.
    /// ```ignore
    /// # use ratatui::layout::Constraint;
    /// # use ratatui::layout::SegmentSize;
    /// # use ratatui::widgets::Table;
    /// let widths = [Constraint::Min(10), Constraint::Min(10), Constraint::Min(10)];
    /// let table = Table::new([], widths)
    ///     .segment_size(SegmentSize::LastTakesRemainder);
    /// ```
    #[stability::unstable(
        feature = "segment-size",
        reason = "The name for this feature is not final and may change in the future",
        issue = "https://github.com/ratatui-org/ratatui/issues/536"
    )]
    #[allow(unexpected_cfgs)]
    pub const fn segment_size(mut self, segment_size: SegmentSize) -> Self {
        self.segment_size = segment_size;
        self
    }

    pub fn selected_row_area(&mut self, state: &mut TableState) -> Option<Rect> {
        let table_area = match &self.block {
            Some(b) => b.inner(self.area),
            None => self.area,
        };

        let mut current_height = 0;
        let mut rows_height = table_area.height;

        // Draw header
        if let Some(ref header) = self.header {
            let max_header_height = table_area.height.min(header.total_height());
            current_height += max_header_height;
            rows_height = rows_height.saturating_sub(max_header_height);
        }

        // Draw rows
        if self.rows.is_empty() {
            self.selected_row_area = None;
            return self.selected_row_area;
        }
        let (start, end) = self.get_row_bounds(state.selected(), state.offset(), rows_height);
        let offset = state.offset_mut();
        *offset = start;
        for (i, table_row) in self
            .rows
            .iter_mut()
            .enumerate()
            .skip(state.offset())
            .take(end - start)
        {
            let (row, inner_offset) = (table_area.top() + current_height, table_area.left());
            current_height += table_row.total_height();
            let table_row_area = Rect {
                x: inner_offset,
                y: row,
                width: table_area.width,
                height: table_row.height,
            };
            let is_selected = *state.selected_mut() == Some(i);
            if is_selected {
                self.selected_row_area = Some(Rect {
                    x: table_row_area.x,
                    y: table_row_area.y + 1,
                    width: table_row_area.width,
                    height: table_row_area.height - 1,
                });
            }
        }
        self.selected_row_area
    }
}

impl<'a> Row<'a> {
    /// Creates a new [`Row`]
    ///
    /// The `cells` parameter accepts any value that can be converted into an iterator of anything
    /// that can be converted into a [`Cell`] (e.g. `Vec<&str>`, `&[Cell<'a>]`, `Vec<String>`, etc.)
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// let row = Row::new(vec!["Cell 1", "Cell 2", "Cell 3"]);
    /// let row = Row::new(vec![
    ///     Cell::new("Cell 1"),
    ///     Cell::new("Cell 2"),
    ///     Cell::new("Cell 3"),
    /// ]);
    /// ```
    pub fn new<T>(cells: T) -> Self
    where
        T: IntoIterator,
        T::Item: Into<Cell<'a>>,
    {
        Self {
            cells: cells.into_iter().map(Into::into).collect(),
            height: 1,
            ..Default::default()
        }
    }

    /// Set the cells of the [`Row`]
    ///
    /// The `cells` parameter accepts any value that can be converted into an iterator of anything
    /// that can be converted into a [`Cell`] (e.g. `Vec<&str>`, `&[Cell<'a>]`, `Vec<String>`, etc.)
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// let row = Row::default().cells(vec!["Cell 1", "Cell 2", "Cell 3"]);
    /// let row = Row::default().cells(vec![
    ///     Cell::new("Cell 1"),
    ///     Cell::new("Cell 2"),
    ///     Cell::new("Cell 3"),
    /// ]);
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn cells<T>(mut self, cells: T) -> Self
    where
        T: IntoIterator,
        T::Item: Into<Cell<'a>>,
    {
        self.cells = cells.into_iter().map(Into::into).collect();
        self
    }

    /// Set the fixed height of the [`Row`]
    ///
    /// Any [`Cell`] whose content has more lines than this height will see its content truncated.
    ///
    /// By default, the height is `1`.
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// let cells = vec!["Cell 1\nline 2", "Cell 2", "Cell 3"];
    /// let row = Row::new(cells).height(2);
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn height(mut self, height: u16) -> Self {
        self.height = height;
        self
    }

    /// Set the bottom margin. By default, the bottom margin is `0`.
    ///
    /// The bottom margin is the number of blank lines to be displayed after the row.
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// # let cells = vec!["Cell 1", "Cell 2", "Cell 3"];
    /// let row = Row::default().bottom_margin(1);
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn bottom_margin(mut self, margin: u16) -> Self {
        self.bottom_margin = margin;
        self
    }

    /// Set the [`Style`] of the entire row
    ///
    /// This [`Style`] can be overridden by the [`Style`] of a any individual [`Cell`] or by their
    /// [`Text`] content.
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// let cells = vec!["Cell 1", "Cell 2", "Cell 3"];
    /// let row = Row::new(cells).style(Style::new().red().italic());
    /// ```
    ///
    /// `Row` also implements the [`Styled`] trait, which means you can use style shorthands from
    /// the [`Stylize`] trait to set the style of the widget more concisely.
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// let cells = vec!["Cell 1", "Cell 2", "Cell 3"];
    /// let row = Row::new(cells).red().italic();
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }
}

impl<'a> Cell<'a> {
    /// Creates a new [`Cell`]
    ///
    /// The `content` parameter accepts any value that can be converted into a [`Text`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// Cell::new("simple string");
    /// Cell::new(Span::from("span"));
    /// Cell::new(Line::from(vec![
    ///     Span::raw("a vec of "),
    ///     Span::styled("spans", Style::default().add_modifier(Modifier::BOLD)),
    /// ]));
    /// Cell::new(Text::from("a text"));
    /// ```
    pub fn new<T>(content: T) -> Self
    where
        T: Into<Text<'a>>,
    {
        Self {
            content: content.into(),
            style: Style::default(),
        }
    }

    /// Set the content of the [`Cell`]
    ///
    /// The `content` parameter accepts any value that can be converted into a [`Text`].
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// Cell::default().content("simple string");
    /// Cell::default().content(Span::from("span"));
    /// Cell::default().content(Line::from(vec![
    ///     Span::raw("a vec of "),
    ///     Span::styled("spans", Style::new().bold()),
    /// ]));
    /// Cell::default().content(Text::from("a text"));
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn content<T>(mut self, content: T) -> Self
    where
        T: Into<Text<'a>>,
    {
        self.content = content.into();
        self
    }

    /// Set the `Style` of this cell
    ///
    /// This `Style` will override the `Style` of the [`Row`] and can be overridden by the `Style`
    /// of the [`Text`] content.
    ///
    /// This is a fluent setter method which must be chained or used as it consumes self
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// Cell::new("Cell 1").style(Style::new().red().italic());
    /// ```
    ///
    /// `Cell` also implements the [`Styled`] trait, which means you can use style shorthands from
    /// the [`Stylize`] trait to set the style of the widget more concisely.
    ///
    /// ```rust
    /// # use ratatui::{prelude::*, widgets::*};
    /// Cell::new("Cell 1").red().italic();
    /// ```
    #[must_use = "method moves the value of self and returns the modified value"]
    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }
}

impl HighlightSpacing {
    /// Determine if a selection column should be displayed
    ///
    /// has_selection: true if a row is selected in the table
    ///
    /// Returns true if a selection column should be displayed
    pub(crate) fn should_add(&self, has_selection: bool) -> bool {
        match self {
            HighlightSpacing::Always => true,
            HighlightSpacing::WhenSelected => has_selection,
            HighlightSpacing::Never => false,
        }
    }
}

impl<'a> Widget for AdvTable<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let mut state = TableState::default();
        StatefulWidget::render(self, area, buf, &mut state);
    }
}

impl<'a> StatefulWidget for AdvTable<'a> {
    type State = TableState;

    fn render(mut self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        if area.area() == 0 {
            return;
        }
        buf.set_style(area, self.style);
        let table_area = match self.block.take() {
            Some(b) => {
                let inner_area = b.inner(area);
                b.render(area, buf);
                inner_area
            }
            None => area,
        };

        let selection_width = if self
            .highlight_spacing
            .should_add(state.selected().is_some())
        {
            self.highlight_symbol.map_or(0, |s| s.width() as u16)
        } else {
            0
        };
        let columns_widths = self.get_columns_widths(table_area.width, selection_width);
        let highlight_symbol = self.highlight_symbol.unwrap_or("");
        let mut current_height = 0;
        let mut rows_height = table_area.height;

        // Draw header
        if let Some(ref header) = self.header {
            let max_header_height = table_area.height.min(header.total_height());
            buf.set_style(
                Rect {
                    x: table_area.left(),
                    y: table_area.top(),
                    width: table_area.width,
                    height: table_area.height.min(header.height),
                },
                header.style,
            );
            let inner_offset = table_area.left();
            for ((x, width), cell) in columns_widths.iter().zip(header.cells.iter()) {
                cell.render(
                    buf,
                    Rect {
                        x: inner_offset + x,
                        y: table_area.top(),
                        width: *width,
                        height: max_header_height,
                    },
                );
            }
            current_height += max_header_height;
            rows_height = rows_height.saturating_sub(max_header_height);
        }

        // Draw rows
        if self.rows.is_empty() {
            return;
        }
        let (start, end) = self.get_row_bounds(state.selected(), state.offset(), rows_height);
        let offset = state.offset_mut();
        *offset = start;
        for (i, table_row) in self
            .rows
            .iter_mut()
            .enumerate()
            .skip(state.offset())
            .take(end - start)
        {
            let (row, inner_offset) = (table_area.top() + current_height, table_area.left());
            current_height += table_row.total_height();
            let table_row_area = Rect {
                x: inner_offset,
                y: row,
                width: table_area.width,
                height: table_row.height,
            };
            buf.set_style(table_row_area, table_row.style);
            let is_selected = *state.selected_mut() == Some(i);
            if selection_width > 0 && is_selected {
                // this should in normal cases be safe, because "get_columns_widths" allocates
                // "highlight_symbol.width()" space but "get_columns_widths"
                // currently does not bind it to max table.width()
                buf.set_stringn(
                    inner_offset,
                    row,
                    highlight_symbol,
                    table_area.width as usize,
                    table_row.style,
                );
            };
            for ((x, width), cell) in columns_widths.iter().zip(table_row.cells.iter()) {
                cell.render(
                    buf,
                    Rect {
                        x: inner_offset + x,
                        y: row,
                        width: *width,
                        height: table_row.height,
                    },
                );
            }
            if is_selected {
                self.selected_row_area = Some(Rect {
                    x: table_row_area.x,
                    y: table_row_area.y + 1,
                    width: table_row_area.width,
                    height: table_row_area.height - 1,
                });
                buf.set_style(table_row_area, self.highlight_style);
            }
        }
    }
}

// private methods for rendering
impl AdvTable<'_> {
    /// Get all offsets and widths of all user specified columns
    /// Returns (x, width)
    fn get_columns_widths(&self, max_width: u16, selection_width: u16) -> Vec<(u16, u16)> {
        let constraints = iter::once(Constraint::Length(selection_width))
            .chain(Itertools::intersperse(
                self.widths.iter().cloned(),
                Constraint::Length(self.column_spacing),
            ))
            .collect_vec();
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(constraints)
            .segment_size(self.segment_size)
            .split(Rect::new(0, 0, max_width, 1));
        layout
            .iter()
            .skip(1) // skip selection column
            .step_by(2) // skip spacing between columns
            .map(|c| (c.x, c.width))
            .collect()
    }

    fn get_row_bounds(
        &self,
        selected: Option<usize>,
        offset: usize,
        max_height: u16,
    ) -> (usize, usize) {
        let offset = offset.min(self.rows.len().saturating_sub(1));
        let mut start = offset;
        let mut end = offset;
        let mut height = 0;
        for item in self.rows.iter().skip(offset) {
            if height + item.height > max_height {
                break;
            }
            height += item.total_height();
            end += 1;
        }

        let selected = selected.unwrap_or(0).min(self.rows.len() - 1);
        while selected >= end {
            height = height.saturating_add(self.rows[end].total_height());
            end += 1;
            while height > max_height {
                height = height.saturating_sub(self.rows[start].total_height());
                start += 1;
            }
        }
        while selected < start {
            start -= 1;
            height = height.saturating_add(self.rows[start].total_height());
            while height > max_height {
                end -= 1;
                height = height.saturating_sub(self.rows[end].total_height());
            }
        }
        (start, end)
    }
}

fn ensure_percentages_less_than_100(widths: &[Constraint]) {
    widths.iter().for_each(|&w| {
        if let Constraint::Percentage(p) = w {
            assert!(
                p <= 100,
                "Percentages should be between 0 and 100 inclusively."
            )
        }
    });
}

// private methods for rendering
impl Row<'_> {
    /// Returns the total height of the row.
    fn total_height(&self) -> u16 {
        self.height.saturating_add(self.bottom_margin)
    }
}

// private methods for rendering
impl Cell<'_> {
    fn render(&self, buf: &mut Buffer, area: Rect) {
        buf.set_style(area, self.style);
        for (i, line) in self.content.lines.iter().enumerate() {
            if i as u16 >= area.height {
                break;
            }

            let x_offset = match line.alignment {
                Some(Alignment::Center) => (area.width / 2).saturating_sub(line.width() as u16 / 2),
                Some(Alignment::Right) => area.width.saturating_sub(line.width() as u16),
                _ => 0,
            };

            let x = area.x + x_offset;
            if x >= area.right() {
                continue;
            }

            buf.set_line(x, area.y + i as u16, line, area.width);
        }
    }
}

impl<'a, T> From<T> for Cell<'a>
where
    T: Into<Text<'a>>,
{
    fn from(content: T) -> Cell<'a> {
        Cell {
            content: content.into(),
            style: Style::default(),
        }
    }
}

impl<'a> Styled for Cell<'a> {
    type Item = Cell<'a>;

    fn style(&self) -> Style {
        self.style
    }

    fn set_style(self, style: Style) -> Self::Item {
        self.style(style)
    }
}

impl<'a> Styled for Row<'a> {
    type Item = Row<'a>;

    fn style(&self) -> Style {
        self.style
    }

    fn set_style(self, style: Style) -> Self::Item {
        self.style(style)
    }
}

impl<'a> Styled for AdvTable<'a> {
    type Item = AdvTable<'a>;

    fn style(&self) -> Style {
        self.style
    }

    fn set_style(self, style: Style) -> Self::Item {
        self.style(style)
    }
}
