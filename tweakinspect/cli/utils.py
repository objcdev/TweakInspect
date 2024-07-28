import enum


class AsciiColor(enum.Enum):
    RED = 196
    GREEN = 46
    YELLOW = 226
    BLUE = 21
    ORANGE = 208
    CYAN = 51
    WHITE = 15
    LIGHT_GRAY = 250
    DARK_GRAY = 240
    BLACK = 0
    PURPLE = 93
    PINK = 198
    BROWN = 130
    LIGHT_BLUE = 39
    LIGHT_GREEN = 120
    LIGHT_YELLOW = 226
    LIGHT_ORANGE = 208
    LIGHT_CYAN = 51
    LIGHT_WHITE = 15
    LIGHT_PURPLE = 93
    BRIGHT_RED = 196
    DARK_GREEN = 22


def style_text_with_color(text: str, color_code: AsciiColor):
    return f"\033[38;5;{color_code.value}m{text}\033[0m"


def build_multicolored_text(text_color_pairs: dict[str, AsciiColor]):
    return "".join([style_text_with_color(k, v) for k, v in text_color_pairs.items()])
