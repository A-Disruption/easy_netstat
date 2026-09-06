fn main() {
    println!("cargo::rerun-if-changed=fonts/icons.toml");
    iced_fontello::build("fonts/icons.toml").expect("Fonts Missing");

    // The taskbar, Alt-Tab and File Explorer all read the icon from the
    // executable's resources, not from the window: iced's window::Settings
    // only reaches ICON_SMALL on Windows, which the taskbar never consults.
    #[cfg(windows)]
    {
        println!("cargo::rerun-if-changed=assets/netstat-rust.ico");

        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("assets/netstat-rust.ico");
        resource.compile().expect("Could not embed the window icon");
    }
}
