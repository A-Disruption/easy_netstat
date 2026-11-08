fn main() {
    // Generated font assets are checked in. Ordinary builds must be offline
    // and must not regenerate tracked source files or contact fontello.com.
    println!("cargo::rerun-if-changed=fonts/icons.ttf");

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
