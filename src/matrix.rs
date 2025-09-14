use crossterm::style::Color;
use rand::{thread_rng, Rng};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    widgets::{Clear, Widget},
};

#[derive(Clone)]
struct MatrixSnowflake {
    x: u16,
    y: f32,
    color: Color,
    shape: char,
    vel: f32,
}

impl MatrixSnowflake {
    pub fn new(area: Rect) -> MatrixSnowflake {
        let mut rng = thread_rng();
        let new_x = rng.gen_range(area.x..area.x + area.width);
        let velocity = rng.gen_range(0.04..0.12);

        MatrixSnowflake {
            x: new_x,
            y: area.y as f32,
            color: Color::Green,
            shape: rng.gen_range(33..127) as u8 as char,
            vel: velocity,
        }
    }

    pub fn within_bounds(&self, area: Rect) -> bool {
        let bottom_edge = area.y + area.height;
        (self.y as u16) < bottom_edge
    }
}

#[derive(Clone)]
pub struct MatrixSnowstorm {
    snowflakes: Vec<MatrixSnowflake>,
    density: usize,
}

impl MatrixSnowstorm {
    pub fn new(area: Rect) -> MatrixSnowstorm {
        MatrixSnowstorm::frame(
            MatrixSnowstorm {
                snowflakes: Vec::new(),
                density: 50,
            },
            area,
        )
    }

    pub fn frame(mut snowstorm: MatrixSnowstorm, area: Rect) -> MatrixSnowstorm {
        let mut rng = thread_rng();

        // Move all the snowflakes, remove if outside the area
        snowstorm.snowflakes.retain_mut(|snowflake| {
            snowflake.y += snowflake.vel;
            snowflake.within_bounds(area)
        });

        // Generate new snowflakes... maybe
        for _ in 0..snowstorm.density {
            if rng.gen_bool(snowstorm.density as f64 / 4000.0) {
                snowstorm.snowflakes.push(MatrixSnowflake::new(area));
            }
        }

        snowstorm
    }
}

impl Widget for MatrixSnowstorm {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Clear the area
        Clear.render(area, buf);

        // Set the snowflakes
        for snowflake in self.snowflakes {
            buf.get_mut(snowflake.x, snowflake.y as u16)
                .set_char(snowflake.shape)
                .set_fg(snowflake.color.into());
        }
    }
}
