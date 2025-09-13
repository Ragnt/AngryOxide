# CI/CD Updates for macOS Support

## Overview

Updated the GitHub Actions CI/CD workflows to support macOS builds and testing alongside the existing Linux targets.

## Files Modified/Created

### 1. `.github/workflows/ci.yml` (Updated)
- Added macOS build targets to the release matrix
- Added `macOS-x86_64` (Intel Macs)
- Added `macOS-aarch64` (Apple Silicon Macs)
- Added Rust target installation step for macOS

### 2. `.github/workflows/ci-macos.yml` (New)
Dedicated macOS CI workflow that includes:
- **Multi-version testing**: Tests on macOS 12, 13, and 14
- **Architecture support**: Both Intel and Apple Silicon
- **Universal binary creation**: Builds fat binaries for both architectures
- **Platform verification**: Checks for Airport, tcpdump, wdutil availability
- **Integration tests**: Runs macOS-specific tests

### 3. `.github/workflows/test.yml` (New)
Cross-platform test workflow that:
- Runs on every push and PR
- Tests both Linux and macOS
- Checks for feature parity
- Verifies no stub implementations remain
- Validates documentation structure

## Key Features Added

### Platform Matrix Testing
```yaml
matrix:
  os: [ubuntu-latest, macos-latest]
  rust: [stable, nightly]
```

### macOS-Specific Checks
- BPF device availability
- Airport utility presence (for older macOS)
- tcpdump availability (for modern macOS)
- wdutil availability
- Monitor mode capability detection

### Universal Binary Support
```bash
# Creates a single binary that works on both Intel and Apple Silicon
lipo -create \
  target/x86_64-apple-darwin/release/angryoxide \
  target/aarch64-apple-darwin/release/angryoxide \
  -output target/universal-apple-darwin/release/angryoxide
```

### Feature Parity Validation
- Tests compile and run on both platforms
- Checks for "not yet implemented" strings
- Validates interface functions work correctly
- Ensures monitor mode code exists for both platforms

## Workflow Triggers

### Release Workflow (`ci.yml`)
- **Trigger**: Git tags (v*)
- **Builds**: Release binaries for all platforms
- **Publishes**: GitHub releases with platform-specific artifacts

### macOS CI (`ci-macos.yml`)
- **Trigger**: Push to main/master/feature branches, PRs
- **Tests**: macOS-specific functionality
- **Creates**: Universal binary artifacts

### Test Workflow (`test.yml`)
- **Trigger**: All pushes and PRs
- **Validates**: Cross-platform compatibility
- **Ensures**: Feature parity

## Build Artifacts

### Linux Artifacts (Existing)
- `angryoxide-linux-x86_64.tar.gz`
- `angryoxide-linux-x86_64-musl.tar.gz`
- `angryoxide-linux-aarch64-musl.tar.gz`
- `angryoxide-linux-arm-musl.tar.gz`
- `angryoxide-linux-armv7hf-musl.tar.gz`
- `angryoxide-linux-aarch64-gnu.tar.gz`

### macOS Artifacts (New)
- `angryoxide-macos-x86_64.tar.gz` - Intel Macs
- `angryoxide-macos-aarch64.tar.gz` - Apple Silicon Macs
- `angryoxide-macos-universal.tar.gz` - Universal binary (both architectures)

## Testing Coverage

### Unit Tests
- Run on both Linux and macOS
- Platform-specific test cases
- Feature parity tests

### Integration Tests
- Interface listing
- Help/version output
- Monitor mode detection
- Hardware capability checks

### Platform-Specific Tests
- **Linux**: nl80211 header checks
- **macOS**: BPF device checks, Airport/tcpdump/wdutil availability

## Benefits

1. **Automated Testing**: Every PR is tested on both platforms
2. **Release Automation**: macOS binaries are built automatically for releases
3. **Feature Parity**: Continuous validation that both platforms have equivalent features
4. **Early Detection**: Catches platform-specific issues before merge
5. **Universal Binary**: Single download works on all Macs

## Future Improvements

1. **Code Signing**: Add macOS code signing for releases
2. **Notarization**: Apple notarization for Gatekeeper approval
3. **Performance Testing**: Add benchmarks comparing Linux vs macOS
4. **Hardware Testing**: Add tests that run on real hardware (self-hosted runners)
5. **Coverage Reports**: Platform-specific code coverage metrics

## Local Testing

Developers can test workflows locally using [act](https://github.com/nektos/act):

```bash
# Test the main CI workflow
act -j test

# Test macOS-specific workflow
act -j test-macos --platform macos-latest=nektos/act-environments-ubuntu:18.04

# Test release builds
act -j test --secret-file .secrets
```

## Monitoring

### Success Indicators
- ✅ All workflows pass on both platforms
- ✅ Release artifacts include macOS binaries
- ✅ No "not yet implemented" warnings
- ✅ Feature parity tests pass

### Failure Recovery
- Workflows are set to `fail-fast: false` to see all failures
- Each platform tests independently
- Manual workflow dispatch available for debugging