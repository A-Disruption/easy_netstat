// Generated automatically by iced_fontello at build time.
// Do not edit manually. Source: ../fonts/icons.toml
// a83b002edd6e8eca98f203b6356ab04080b435aadaaaa5bdb7ba5f24e94dcd41
use iced::widget::{text, Text};
use iced::Font;

pub const FONT: &[u8] = include_bytes!("../fonts/icons.ttf");

pub fn refresh<'a>() -> Text<'a> {
    icon("\u{1F504}")
}

pub fn settings<'a>() -> Text<'a> {
    icon("\u{2699}")
}

fn icon(codepoint: &str) -> Text<'_> {
    text(codepoint).font(Font::with_name("icons"))
}
