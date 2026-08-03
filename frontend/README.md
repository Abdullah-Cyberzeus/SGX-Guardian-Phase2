# SG-X Guardian — Admin Console

**Project**: SG-X Guardian Mobile Web App

**Phase**: Phase 1 — Full Ground-Up Redesign & Production Build

**Stack**: React 18 + React Router 7 + TypeScript + Vite

**Document Date**: May 2026

## Executive Summary

The SG-X Guardian is the companion mobile web application for the Cervais SG-X Gateway Device — a hardware security appliance that protects critical infrastructure edge environments across energy, healthcare, federal/defense, transportation, manufacturing, and agriculture sectors.

This repository contains the production — a mobile browser-based web app (PWA-compatible) that enables field security engineers and circle admins to monitor Guardian health, triage alerts, manage Circle of Trust membership, control connected devices, and configure system settings.

## Value Proposition

| Area | Value Delivered |
|------|----------------|
| **Security at a Glance** | Health Score dashboard communicates Guardian status in under 3 seconds |
| **Alert Triage** | View → understand → act on threats in under 4 taps with AI recommendations |
| **Circle of Trust** | Manage cryptographically verified peer groups, secure chat, voice/video calls |
| **Device Management** | Full control over connected devices, smart home integrations, and automation rules |
| **Field-First Design** | Mobile-optimized, one-handed use, low-light environments, WCAG AA compliant |

## Technical Architecture

### Core Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **UI Framework** | React 18 | Component-based UI with concurrent rendering |
| **Routing** | React Router 7 | Client-side routing with nested layouts |
| **Backend API** | SGX Guardian (`new-guardian`) | Rust/Axum REST API on `http://127.0.0.1:8443/api/v1` |
| **Language** | TypeScript | Type-safe development |
| **Build Tool** | Vite 6 | Fast dev server and optimized production builds |
| **Styling** | Tailwind CSS | Utility-first CSS with Cervais brand tokens |

### Platform Specification

| Attribute | Specification |
|-----------|--------------|
| **Type** | Mobile browser-based web app (PWA-compatible) |
| **Distribution** | Browser URL (not App Store / Play Store) |
| **Primary Target** | iOS Safari, Android Chrome |
| **Base Design Width** | 390px (iPhone 14) |
| **Responsive Range** | 360px – 430px mobile viewport |
| **Accessibility** | WCAG AA |

### App Structure

The app is organized into 6 functional zones:

| Zone | Access | Description |
|------|--------|-------------|
| **Onboarding** | First run only | Hardware pairing, account setup, first Circle creation |
| **Home** | Bottom nav tab 1 | Guardian health score, alert summary, quick actions |
| **Alerts** | Bottom nav tab 2 | Full alert management, AI threat intelligence |
| **Network** | Bottom nav tab 3 | Circle of Trust — team, chat, calls, topology |
| **Devices** | Bottom nav tab 4 | Connected device management, smart home integration |
| **Settings** | Bottom nav tab 5 | Guardian config, account, DID, preferences |

## Getting Started

### Prerequisites

- Node.js (v18+)
- npm
- SGX Guardian backend (`new-guardian`) running on port 8443
- Nebula mesh daemon running (`sudo nebula -config /var/lib/sgx-guardian/nebula/nebula.yaml`)

### Environment Variables

```bash
cp .env.example .env.local
```

Required variables:

```
VITE_API_URL=http://127.0.0.1:8443/api/v1
```

### Development

```bash
# 1. Start Nebula daemon (required for backend)
sudo nebula -config /var/lib/sgx-guardian/nebula/nebula.yaml > /tmp/nebula.log 2>&1 &

# 2. Start backend nodes (from new-guardian directory)
cargo run -- nodeA   # CA/Lighthouse — starts REST API on :8443
cargo run -- nodeB
cargo run -- nodeC

# 3. Start frontend (from SGX-gaurdian-admi-console-FE/next-app or root)
npm install
npm run dev          # Vite dev server on http://localhost:5173
```

### Build

```bash
# Production build
npm run build

# Preview production build
npm run preview
```

## Project Documentation

| Document | Description |
|----------|-------------|
| [Product Brief](docs/product/product-brief.md) | Executive summary, problem statement, product vision, full feature set |
| [User Personas](docs/product/user-personas.md) | Field Security Engineer and Circle Admin persona definitions |
| [Screen Inventory](docs/product/screen-inventory.md) | Master catalog of every screen, modal, and state |
| [Information Architecture](docs/information-architecture.md) | Full sitemap, navigation structure, state architecture |
| [API Requirements](docs/api-requirements.md) | Every API endpoint the frontend requires from the backend |
| [Auth & Realtime](docs/auth-and-realtime.md) | Authentication flows + WebSocket real-time requirements |
| [User Flows Overview](docs/flows/README.md) | Introduction to user flow documentation |
| [Onboarding Flow](docs/flows/onboarding.md) | First-run hardware pairing and account setup |
| [Alert Triage Flow](docs/flows/alert-triage.md) | Threat detection → investigation → resolution |
| [Circle Flow](docs/flows/circle.md) | Circle creation, member management, communication |
| [SG-X Device Flow](docs/flows/sgx-device.md) | Guardian device management and configuration |
| [Smart Home Flow](docs/flows/smart-home-integration.md) | Hub/dongle/cloud service integration |
| [Settings Flow](docs/flows/settings.md) | App and Guardian configuration |

## Development Workflow

### Repository & Branching

- **Repository**: Cervais GitHub Organization
- **Branching Strategy**: Main branch protected, requires PR approval
- **Status Checks**: All CI/CD checks must pass before merge

### API Integration

- **Base URL**: `http://127.0.0.1:8443/api/v1` (configured via `VITE_API_URL`)
- **Backend**: SGX Guardian Rust/Axum server — start with `cargo run -- nodeA` from `new-guardian/`
- **Mock Data**: `/src/app/data/mockData.ts` — used only as null fallback for endpoints not yet on the backend (alerts, circles, threat intel). All security-critical screens (PCR, DKP, boot status, attestation, policy, logs) use live API data.

## Security

This is a security-critical application managing industrial edge infrastructure. All contributions must:

- Pass linting and type checks
- Include appropriate test coverage
- Be reviewed and approved before merging
- Follow secure coding practices (no XSS, no token leakage, no sensitive data in client state)

## License

[License information to be added]

## Contact

For questions or issues, please contact:

- **Client**: Pouya Barrach-Yousefi <pouya@cervais.com>
- **Design & Frontend**: Lightning Leap Analytics Pvt. Ltd.
