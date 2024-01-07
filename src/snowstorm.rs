use rand::{thread_rng, Rng};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::Color,
    widgets::{Clear, Widget},
};

const SNOW_1: char = '❄';
const SNOW_2: char = '❆';
const SNOW_3: char = '❋';
const SNOW_4: char = '❅';
const SNOW_5: char = '❊';
const SNOW_6: char = '❉';

const SNOWFLAKES: [char; 6] = [SNOW_1, SNOW_4, SNOW_2, SNOW_6, SNOW_5, SNOW_3];

const GRAYSCALE: [Color; 4] = [
    Color::Indexed(255),
    Color::Indexed(250),
    Color::Indexed(245),
    Color::Indexed(240),
];

#[derive(Clone)]
pub struct Snowstorm {
    snowflakes: Vec<Snowflake>,
    density: usize,
    rainbow: bool,
}

impl Snowstorm {
    pub fn new(area: Rect) -> Snowstorm {
        Snowstorm::frame(
            Snowstorm {
                snowflakes: Vec::new(),
                density: 20,
                rainbow: false,
            },
            area,
        )
    }

    pub fn new_rainbow(area: Rect) -> Snowstorm {
        Snowstorm::frame(
            Snowstorm {
                snowflakes: Vec::new(),
                density: 20,
                rainbow: true,
            },
            area,
        )
    }

    pub fn frame(mut snowstorm: Snowstorm, area: Rect) -> Snowstorm {
        let mut rng = thread_rng();

        // Move all the snowflakes, remove if outside the area
        snowstorm.snowflakes.retain_mut(|snowflake| {
            // Slow down vertical movement by using a smaller increment
            snowflake.y += snowflake.vel;

            if rng.gen_bool(0.001) {
                let drift = rng.gen_range(-1..=1);
                snowflake.x = ((snowflake.x as i32) + (drift) as i32) as u16;
            }

            snowflake.within_bounds(area)
        });

        // Generate new snowflakes... maybe
        for _ in 0..snowstorm.density {
            if rng.gen_bool(snowstorm.density as f64 / 5000.0) {
                snowstorm
                    .snowflakes
                    .push(Snowflake::new(area, snowstorm.rainbow));
            }
        }

        snowstorm
    }
}

impl Widget for Snowstorm {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Clear the area
        Clear.render(area, buf);
        // Set the snowflakes
        for snowflake in self.snowflakes {
            buf.get_mut(snowflake.x, snowflake.y as u16)
                .set_char(snowflake.shape)
                .set_fg(snowflake.color);
        }
    }
}
#[derive(Clone)]
struct Snowflake {
    x: u16,
    y: f32,
    color: Color,
    shape: char,
    vel: f32,
}

impl Snowflake {
    pub fn new(area: Rect, rainbow: bool) -> Snowflake {
        // Set it to a grayscale color at random to create depth
        let mut color = GRAYSCALE[rand::random::<usize>() % 4];

        // If we doing the rainbow thing
        if rainbow {
            let rd_r = rand::random::<u8>();
            let rd_g = rand::random::<u8>();
            let rd_b = rand::random::<u8>();
            color = Color::Rgb(rd_r, rd_g, rd_b)
        }

        let left_edge = area.x;
        let right_edge = area.x + area.width;

        let mut rng = thread_rng();
        let new_x = rng.gen_range(left_edge..right_edge);

        let velocity = rng.gen_range(0.04..0.08);

        Snowflake {
            x: new_x,
            y: area.y as f32,
            color,
            shape: SNOWFLAKES[rand::random::<usize>() % 6],
            vel: velocity,
        }
    }

    pub fn within_bounds(&self, area: Rect) -> bool {
        let left_edge = area.x;
        let right_edge = area.x + area.width;
        let top_edge = area.y;
        let bottom_edge = area.y + area.height;

        self.x >= left_edge
            && self.x <= right_edge
            && (self.y as u16) >= top_edge
            && (self.y as u16) < bottom_edge
    }
}
