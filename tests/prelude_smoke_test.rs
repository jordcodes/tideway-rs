use tideway::prelude::*;

#[test]
fn prelude_core_items_are_usable() {
    let _config = ConfigBuilder::new().build().expect("valid default config");
    let _app = App::new();
}
