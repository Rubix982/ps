# Use a Debian image as the base image for the builder stage
FROM debian:bullseye-slim as builder

# Install Rust and required dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates

# Install rustup and set env variables
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

# Set environment variables
ENV PATH="/root/.cargo/bin:${PATH}"

# App name from Cargo.toml
ARG APP_NAME=mcc

# Set the working directory inside the container
WORKDIR /app

# Install dependencies for the SSL certificates
RUN curl https://curl.se/ca/cacert.pem --output /etc/ssl/ca-certificates.crt

# Copy the Cargo.toml and Cargo.lock files
COPY Cargo.toml Cargo.lock ./

# Build dependencies without the actual source code
RUN mkdir src && echo "// dummy file" > src/lib.rs && /root/.cargo/bin/cargo build --release

# Remove dummy `src` folder
RUN rm -rf src

# Copy the source code into the container
COPY src src

# Build the Rust application
RUN cargo build --locked --release

# Move target binary
RUN cp ./target/release/mcc /bin/server

# Create non-privileged user
RUN adduser \
	--disabled-password \
	--gecos "" \
	--home "/nonexistent" \
	--no-create-home \
	--uid "10001" \
	appuser

# Change to non-privileged user
USER appuser

# Start a new stage to create the final lightweight container
FROM alpine:latest

# Install ca-certificates in the final image
RUN apk update && apk add -y --no-cache ca-certificates

# Copy the built binary from the builder stage
COPY --from=builder /app/target/release/mcc /app/mcc

# Set the working directory inside the container
WORKDIR /app

# Expose any necessary ports
EXPOSE 8080

# Change to non-privileged user
USER 10001

# Command to run the executable
CMD ["./mcc"]

