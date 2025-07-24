# Identity Spoofing Detection Service

## Overview

This project is an advanced Identity Spoofing Detection Service designed to detect suspicious login patterns by analyzing device fingerprints, geolocations, and access metadata. It leverages a Ruby on Rails API (with GraphQL) for user management and authentication, and a Rust-based detection engine for high-performance risk analysis. SDKs are provided for web and other platforms.

---

## Architecture

- **Ruby on Rails API**: Handles authentication, user management, and exposes a GraphQL API for client interaction.
- **Rust Detection Engine**: Performs real-time analysis of login attempts, device fingerprints, and behavioral patterns to assess risk.
- **Client SDKs**: Facilitate integration with web, Android, and iOS clients.

```
[Client SDKs] <-> [Rails API/GraphQL] <-> [Rust Detection Engine]
```

---

## Features

- User registration and authentication (GraphQL mutations)
- Device fingerprinting and metadata collection
- Risk scoring and anomaly detection for login attempts
- Query login history and risk assessments

---

## Setup & Installation

### Prerequisites
- Ruby (>= 3.0)
- Rails (>= 7.0)
- Rust (>= 1.60)
- Node.js (for web SDK)
- PostgreSQL (recommended)

### 1. Clone the repository
```sh
git clone <repo-url>
cd Odin
```

### 2. Setup the Rails API
```sh
cd odin/api
bundle install
# TODO: Add database setup instructions
# TODO: Add environment variable setup
```

### 3. Setup the Rust Detection Engine
```sh
cd ../detection-engine
cargo build --release
# TODO: Add instructions for running as a service or integrating with Rails
```

### 4. Setup the Web SDK (optional)
```sh
cd ../client-sdks/web
npm install
# TODO: Add build and usage instructions
```

---

## API Usage

### GraphQL Queries
- `me`: Get the currently authenticated user
- `loginHistory(limit: Int)`: Get recent login attempts
- `riskAssessment(loginAttemptId: ID!)`: Get risk assessment for a login attempt

### GraphQL Mutations
- `login`: User login
- `register`: User registration
- `recordFingerprint`: Record a device fingerprint
- `verifySession`: Verify an active session

> See the `odin/api/app/graphql/types/query_type.rb` and `mutation_type.rb` for schema details.

---

## Contributing

1. Fork the repo and create a feature branch.
2. Follow the code style guidelines (see `.rubocop.yml` and `rustfmt.toml`).
3. Add tests for new features (RSpec for Ruby, built-in for Rust).
4. Submit a pull request with a clear description.

---

## Directory Structure

- `odin/api/` - Rails API backend
- `odin/detection-engine/` - Rust detection engine
- `odin/client-sdks/` - Client SDKs (web, android, ios)
- `odin/scripts/` - Setup, seed, and benchmark scripts
- `odin/docs/` - Documentation (architecture, API, deployment)

---

