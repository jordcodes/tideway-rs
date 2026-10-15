//! Naming helpers shared by scaffolding commands.

/// Words whose plural is not formed by a general English rule.
const IRREGULAR: &[(&str, &str)] = &[
    ("child", "children"),
    ("foot", "feet"),
    ("goose", "geese"),
    ("man", "men"),
    ("mouse", "mice"),
    ("person", "people"),
    ("quiz", "quizzes"),
    ("tooth", "teeth"),
    ("woman", "women"),
];

/// Words that are the same in singular and plural.
const UNCOUNTABLE: &[&str] = &[
    "data",
    "equipment",
    "feedback",
    "fish",
    "information",
    "metadata",
    "news",
    "series",
    "sheep",
    "species",
];

/// Pluralizes a snake_case resource name. Only the last word changes, so
/// `product_category` becomes `product_categories`.
pub(crate) fn pluralize(name: &str) -> String {
    let (prefix, word) = match name.rfind('_') {
        Some(index) => name.split_at(index + 1),
        None => ("", name),
    };
    format!("{prefix}{}", pluralize_word(word))
}

fn pluralize_word(word: &str) -> String {
    if word.is_empty() || UNCOUNTABLE.contains(&word) {
        return word.to_string();
    }
    if let Some((_, plural)) = IRREGULAR.iter().find(|(singular, _)| *singular == word) {
        return (*plural).to_string();
    }

    if let Some(stem) = word.strip_suffix('y')
        && stem.ends_with(|c: char| c.is_ascii_alphabetic() && !"aeiou".contains(c))
    {
        return format!("{stem}ies");
    }
    if ["s", "x", "z", "ch", "sh"]
        .iter()
        .any(|suffix| word.ends_with(suffix))
    {
        return format!("{word}es");
    }
    format!("{word}s")
}

#[cfg(test)]
mod tests {
    use super::pluralize;

    #[test]
    fn pluralizes_resource_names() {
        let cases = [
            ("todo", "todos"),
            ("user", "users"),
            ("category", "categories"),
            ("company", "companies"),
            ("key", "keys"),
            ("status", "statuses"),
            ("box", "boxes"),
            ("match", "matches"),
            ("dish", "dishes"),
            ("person", "people"),
            ("quiz", "quizzes"),
            ("metadata", "metadata"),
            ("feedback", "feedback"),
            ("product_category", "product_categories"),
            ("daily_quiz", "daily_quizzes"),
        ];
        for (singular, expected) in cases {
            assert_eq!(pluralize(singular), expected, "pluralize({singular:?})");
        }
    }
}
