# Use Ubuntu latest as base (similar to GitHub Actions ubuntu-latest)
FROM ubuntu:22.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install clippy and fmt
RUN rustup component add clippy rustfmt

# Set working directory
WORKDIR /app

# Copy the entire project
COPY . .

# Build the project
RUN cargo build --release

# Run tests by default
CMD ["cargo", "test"]