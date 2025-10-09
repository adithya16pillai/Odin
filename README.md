# Identity Spoofing Detection Service

## Overview

This project is an advanced Identity Spoofing Detection Service designed to detect suspicious login patterns by analyzing device fingerprints, geolocations, and access metadata. It leverages a Ruby on Rails API (with GraphQL) for user management and authentication, and a Rust-based detection engine for high-performance risk analysis. SDKs are provided for web and other platforms.


## Architecture

- **Ruby on Rails API**: Handles authentication, user management, and exposes a GraphQL API for client interaction.
- **Rust Detection Engine**: Performs real-time analysis of login attempts, device fingerprints, and behavioral patterns to assess risk.
- **Client SDKs**: Facilitate integration with web, Android, and iOS clients.

## Features

- User registration and authentication (GraphQL mutations)
- Device fingerprinting and metadata collection
- Risk scoring and anomaly detection for login attempts
- Query login history and risk assessments


## Setup & Installation

### Prerequisites
- Ruby (>= 3.0)
- Rails (>= 7.0)
- Rust (>= 1.60)
- Node.js (for web SDK)
- PostgreSQL (recommended)

