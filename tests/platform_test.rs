// Simple integration test to verify platform compilation

#[test]
fn test_platform_detection() {
    #[cfg(target_os = "macos")]
    {
        println!("Running on macOS");
        assert!(cfg!(target_os = "macos"));
    }

    #[cfg(target_os = "linux")]
    {
        println!("Running on Linux");
        assert!(cfg!(target_os = "linux"));
    }
}

#[test]
fn test_build_succeeds() {
    // This test just ensures the build completes successfully
    // Build completed successfully
}
