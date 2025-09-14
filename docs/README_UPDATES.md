# README Updates for macOS Support

## Summary

Updated the main README.md to include comprehensive information for macOS users, making AngryOxide accessible to a wider audience.

## Changes Made

### 1. Title Enhancement
- Added "Now with macOS support! 🍎" to highlight cross-platform capability

### 2. Quick Compatibility Check
Added upfront compatibility information:
- **Linux**: Full support
- **macOS**: Supported with limitations
- **Windows**: Not supported (WSL2 recommended)

### 3. Installation Instructions
Split into platform-specific sections:
- **Linux**: Existing instructions maintained
- **macOS**: Added instructions for Intel, Apple Silicon, and Universal binaries
- Added macOS system requirements

### 4. Platform Support Matrix
Created comprehensive compatibility table showing:
- Platform/Architecture combinations
- Monitor mode support levels
- Packet injection capabilities
- Stability status

### 5. Building from Source
Separated Linux and macOS instructions:
- macOS-specific requirements (Xcode tools)
- Platform-appropriate installation paths
- Completions setup for macOS

### 6. macOS-Specific Notes Section
Comprehensive section covering:
- **Monitor Mode Methods**: Airport vs tcpdump
- **Known Limitations**: Apple Silicon, SIP, channel hopping
- **Recommended Hardware**: Best adapters and Mac models
- **Troubleshooting**: Common issues and solutions

### 7. Interface Examples
Updated help text to show platform-specific interface names:
- Linux: wlan0
- macOS: en0

## User Benefits

### For macOS Users
- Clear understanding of capabilities and limitations
- Step-by-step installation instructions
- Hardware recommendations for best results
- Troubleshooting guide for common issues

### For All Users
- Immediate platform compatibility visibility
- Clearer installation process
- Better understanding of cross-platform differences

## Key Information Highlighted

1. **Apple Silicon Limitations**: Users know upfront about M1/M2/M3 limitations
2. **Monitor Mode Methods**: Clear explanation of Airport vs tcpdump
3. **Hardware Recommendations**: Specific adapter models for best results
4. **SIP Requirements**: Clear note about MAC spoofing requirements
5. **Channel Hopping**: Performance expectations set appropriately

## Documentation Structure

The README now follows a logical flow:
1. Introduction & Compatibility
2. Installation (platform-specific)
3. Features & Capabilities
4. Platform Support Details
5. Usage & Help
6. Building from Source
7. Platform-Specific Notes
8. Troubleshooting

This structure allows users to quickly find relevant information for their platform while maintaining comprehensive documentation for all users.