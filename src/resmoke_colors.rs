use colored::Color;
use lazy_regex::{lazy_regex, Lazy};
use regex::Regex;

pub struct ResmokeComponentColors {
    pub default_color: Color,
    pub children_by_regex: Vec<(Regex, ResmokeComponentColors)>,
}

lazy_static::lazy_static! {
    pub static ref RESMOKE_COMPONENT_REGEXES: ResmokeComponentColors = default_resmoke_colors();
}

fn mk_component(color: Color) -> ResmokeComponentColors {
    ResmokeComponentColors {
        default_color: color,
        children_by_regex: vec![],
    }
}

fn from_rgb(r: u8, g: u8, b: u8) -> Color {
    Color::TrueColor { r, g, b }
}

type ResmokeColorPolicy = (Regex, ResmokeComponentColors);

fn color_for_port(prefix: &str, last_digit: &str, color: Color) -> ResmokeColorPolicy {
    (
        Regex::new(format!(r"{}\d+{}\|", prefix, last_digit).as_str()).unwrap(),
        ResmokeComponentColors {
            default_color: color,
            children_by_regex: vec![],
        },
    )
}

fn blue_no(n: usize) -> Color {
    return *vec![
        from_rgb(0, 0, 255),     // True Blue.
        from_rgb(135, 206, 235), // Sky Blue.
        from_rgb(137, 207, 240), // Baby Blue.
        from_rgb(70, 130, 180),  // Steel Blue.
        from_rgb(86, 160, 211),  // Carolina Blue.
        from_rgb(0, 97, 112),    // Turkish Blue.
        from_rgb(115, 194, 251), // Maya Blue.
        from_rgb(0, 0, 128),     // Navy Blue.
        from_rgb(15, 82, 186),   // Sapphire.
        from_rgb(0, 49, 81),     // Prussian Blue.
        // 10
        from_rgb(176, 224, 230), // Powder Blue.
        from_rgb(125, 249, 255), // Electric Blue.
        from_rgb(54, 117, 136),  // Teal Blue.
        from_rgb(153, 255, 255), // Ice Blue.
        from_rgb(91, 146, 229),  // Horizon Blue.
        from_rgb(73, 151, 208),  // Celestial Blue.
        from_rgb(84, 90, 167),   // Liberty Blue.
        from_rgb(76, 81, 109),   // Independence Blue.
        from_rgb(93, 138, 168),  // Air Force Blue.
        from_rgb(15, 77, 146),   // Yale Blue.
    ]
    .get(n)
    .unwrap();
}

fn green_no(n: usize) -> Color {
    return *vec![
        from_rgb(0, 255, 0),     // Lime Green.
        from_rgb(34, 139, 34),   // Forest Green.
        from_rgb(46, 139, 87),   // Sea Green.
        from_rgb(128, 128, 0),   // Olive Green.
        from_rgb(152, 251, 152), // Mint Green.
        from_rgb(76, 187, 23),   // Kelly Green.
        from_rgb(0, 128, 128),   // Teal Green.
        from_rgb(0, 168, 107),   // Jade Green.
        from_rgb(80, 200, 120),  // Emerald Green.
        from_rgb(120, 134, 107), // Sage Green.
        // 10
        from_rgb(152, 255, 152), // Mint Green.
        from_rgb(41, 171, 135),  // Jungle Green.
        from_rgb(79, 121, 66),   // Fern Green.
        from_rgb(1, 121, 111),   // Pine Green.
        from_rgb(53, 94, 59),    // Hunter Green.
        from_rgb(109, 157, 85),  // Juniper Green.
        from_rgb(188, 184, 138), // Sage Green.
        from_rgb(107, 142, 35),  // Olive Drab Green.
        from_rgb(0, 158, 96),    // Shamrock Green.
        from_rgb(80, 200, 120),  // Emerald Green.
    ]
    .get(n)
    .unwrap();
}

fn orange_no(n: usize) -> Color {
    return *vec![
        from_rgb(255, 165, 0),   // Bright Orange.
        from_rgb(255, 117, 24),  // Pumpkin Orange.
        from_rgb(255, 127, 80),  // Coral.
        from_rgb(240, 128, 0),   // Tangerine.
        from_rgb(255, 191, 0),   // Amber.
        from_rgb(251, 206, 177), // Apricot.
        from_rgb(204, 85, 0),    // Burnt Orange.
        from_rgb(255, 229, 180), // Peach.
        from_rgb(255, 95, 31),   // Neon Orange.
        from_rgb(242, 140, 40),  // Cadmium Orange.
        // 10
        from_rgb(253, 94, 83),   // Sunset Orange.
        from_rgb(255, 204, 102), // Cantaloupe Orange.
        from_rgb(237, 145, 33),  // Carrot Orange.
        from_rgb(255, 99, 71),   // Fire Orange.
        from_rgb(250, 128, 114), // Salmon Orange.
        from_rgb(255, 99, 71),   // Tomato Orange.
        from_rgb(255, 194, 77),  // Honey Orange.
        from_rgb(255, 88, 0),    // Tiger Orange.
        from_rgb(234, 142, 68),  // Cinnamon Orange.
        from_rgb(245, 134, 52),  // Chili Orange.
    ]
    .get(n)
    .unwrap();
}

fn colors_for_fixture_ports_offset(offset: usize) -> Vec<ResmokeColorPolicy> {
    let mongod_in_blue = |i: usize| -> ResmokeColorPolicy {
        color_for_port("d", &i.to_string(), blue_no(offset + i))
    };
    let mongos_in_green = |i: usize| -> ResmokeColorPolicy {
        color_for_port("s", &i.to_string(), green_no(offset + i))
    };
    let config_in_orange = |i: usize| -> ResmokeColorPolicy {
        color_for_port("c", &i.to_string(), orange_no(offset + i))
    };
    let mut result: Vec<ResmokeColorPolicy> = (0..10).map(mongod_in_blue).collect();
    result.extend((0..10).map(mongos_in_green));
    result.extend((0..10).map(config_in_orange));
    result
}

fn colors_for_fixture_ports_0() -> Vec<ResmokeColorPolicy> {
    colors_for_fixture_ports_offset(0)
}

fn colors_for_fixture_ports_1() -> Vec<ResmokeColorPolicy> {
    colors_for_fixture_ports_offset(10)
}

fn resmoke_fixture_colors() -> Vec<ResmokeColorPolicy> {
    vec![
        (Regex::new("s").unwrap(), mk_component(blue_no(0))),
        (Regex::new("c").unwrap(), mk_component(blue_no(1))),
        (
            Regex::new("s0").unwrap(),
            ResmokeComponentColors {
                default_color: blue_no(2),
                children_by_regex: vec![
                    (Regex::new("prim").unwrap(), mk_component(blue_no(3))),
                    (Regex::new("sec").unwrap(), mk_component(blue_no(4))),
                ],
            },
        ),
        (
            Regex::new("s1").unwrap(),
            ResmokeComponentColors {
                default_color: blue_no(5),
                children_by_regex: vec![
                    (Regex::new("prim").unwrap(), mk_component(blue_no(6))),
                    (Regex::new("sec").unwrap(), mk_component(blue_no(7))),
                ],
            },
        ),
        (Regex::new("s2").unwrap(), mk_component(blue_no(8))),
        (Regex::new("s3").unwrap(), mk_component(blue_no(9))),
    ]
}

fn job0_colors() -> ResmokeColorPolicy {
    let mut j0_children = resmoke_fixture_colors();
    j0_children.extend(vec![(
        Regex::new("js_test").unwrap(),
        ResmokeComponentColors {
            default_color: Color::BrightBlue,
            children_by_regex: vec![(
                Regex::new(".*").unwrap(),
                ResmokeComponentColors {
                    default_color: Color::BrightBlue,
                    children_by_regex: colors_for_fixture_ports_0(),
                },
            )],
        },
    )]);
    (
        Regex::new("j0").unwrap(),
        ResmokeComponentColors {
            default_color: Color::Blue,
            children_by_regex: j0_children,
        },
    )
}

fn job1_colors() -> ResmokeColorPolicy {
    (
        Regex::new("j1").unwrap(),
        ResmokeComponentColors {
            default_color: Color::Magenta,
            children_by_regex: vec![(
                Regex::new("js_test").unwrap(),
                ResmokeComponentColors {
                    default_color: Color::BrightMagenta,
                    children_by_regex: vec![(
                        Regex::new(".*").unwrap(),
                        ResmokeComponentColors {
                            default_color: Color::BrightMagenta,
                            children_by_regex: colors_for_fixture_ports_1(),
                        },
                    )],
                },
            )],
        },
    )
}

fn other_job_colors() -> ResmokeColorPolicy {
    (
        Regex::new("j[2-9]\\d*").unwrap(),
        ResmokeComponentColors {
            default_color: Color::Magenta,
            children_by_regex: vec![(
                Regex::new("js_test").unwrap(),
                ResmokeComponentColors {
                    default_color: Color::BrightMagenta,
                    children_by_regex: vec![(
                        Regex::new(".*").unwrap(),
                        ResmokeComponentColors {
                            default_color: Color::BrightMagenta,
                            children_by_regex: colors_for_fixture_ports_1(),
                        },
                    )],
                },
            )],
        },
    )
}

fn default_resmoke_colors() -> ResmokeComponentColors {
    ResmokeComponentColors {
        default_color: from_rgb(150, 150, 150),
        children_by_regex: vec![
            (
                Regex::new("resmoke").unwrap(),
                mk_component(from_rgb(100, 100, 100)),
            ),
            (
                Regex::new("executor").unwrap(),
                mk_component(from_rgb(40, 40, 40)),
            ),
            job0_colors(),
            job1_colors(),
            other_job_colors(),
            (
                Regex::new("js_test").unwrap(),
                ResmokeComponentColors {
                    default_color: Color::Magenta,
                    children_by_regex: vec![
                        (
                            Regex::new(".*").unwrap(),
                            ResmokeComponentColors {
                                default_color: Color::Magenta,
                                children_by_regex: colors_for_fixture_ports_0(),
                            },
                        ),
                        (
                            Regex::new(r"job\d+_fixture_teardown").unwrap(),
                            ResmokeComponentColors {
                                default_color: Color::Magenta,
                                children_by_regex: vec![],
                            },
                        ),
                    ],
                },
            ),
        ],
    }
}

pub static RESMOKE_FORMAT: Lazy<Regex> = lazy_regex!(r"(\[\S+\] (?:[cdsh]\d+\| )?)(.*)");

pub static RESMOKE_LOG_SUCCESS: Lazy<Regex> =
    lazy_regex!(r#"All \d+ test\(s\) passed|Exiting with code: 0"#);
