![Sovratis Light](github_assets/img/sovratis-Light.png#gh-light-mode-only)
![Sovratis Dark](github_assets/img/Sovratis.png#gh-dark-mode-only)


# Sovratis Sovereign Cloud Manager (Based on CIPP)

## What is the Sovereign Cloud Manager?

The Sovratis Sovereign Cloud Manager is an enterprise-grade extension of the CyberDrain Improved Partner Portal (CIPP). While the original CIPP is a powerful multi-tenant management portal for standard Microsoft Partners, it assumes full Microsoft 365 feature parity across all environments. 

This assumption fails in **Sovereign Clouds** (e.g., the German DELOS Cloud) due to strict compliance, data residency boundaries, and limited feature sets. Executing standard API calls in these environments leads to silent failures, UI errors, or severe compliance breaches. 

To solve this, **Sovratis Consulting** has engineered a sovereign-compliant overlay. It implements a **Gatekeeper Architecture**—a validation middleware that intercepts, evaluates, and filters API requests based on strict tenant-environment capabilities, while maintaining absolute data sovereignty.

## Core Architectural Pillars & Features

In addition to standard CIPP capabilities (tenant administration, standards enforcement, and automation), this repository introduces:

- **Validation Middleware & Feature Gating:** An API interceptor layer that evaluates every request against a predefined `CloudEnvironmentType` matrix. Unsupported actions (e.g., specific Copilot or advanced security features not available in Sovereign Clouds) are blocked pre-flight with clean HTTP 403 responses and UI feedback.
- **Zero Upstream Debt:** The core CIPP repository remains untouched. All sovereign-specific routing and filtering occur within the middleware, allowing seamless upstream merges and patch management from the CIPP community.
- **Absolute Data Sovereignty (DKE):** Integrated Double Key Encryption (DKE) pattern for all sensitive configuration data and token caches. Utilizes an external, dedicated Hardware Security Module (HSM) or Cloud PKI to ensure the US cloud provider has zero capability to decrypt tenant data.
- **Native SOC Integration:** Built-in telemetry forwarder. Every blocked API call, authentication attempt, and cryptographic operation is sanitized (masking PII) and forwarded via CEF/JSON to an external Security Operations Center (SOC) for real-time monitoring.

## How it works

This repository is a containerized monorepo powered by the Craft runtime, extending the original CIPP structure with a dedicated Sovereign Middleware layer:

- **`src/SovereignMiddleware/`** — **[SOVRATIS IP]** The core API Gateway and validation engine intercepting frontend-to-backend communication.
- **`frontend/`** — The web interface, built with [Next.js](https://nextjs.org/) and React.
- **`backend/`** — The CIPP API layer, written in PowerShell and executed by the Craft runtime. *(Kept strictly upstream-compatible)*.
- **`build/`** — Dockerfiles, docker-compose definitions, and tooling used to build and run the containerized deployment, including the proxy routing.

## Intellectual Property & Maintainer

Designed and maintained by **Sovratis Consulting** – Specialized in B2B IT Security, Enterprise Cloud Architecture, and Sovereign Data Protection.

For enterprise licensing, SOC integration inquiries, or Sovereign Cloud consulting, visit [sovratis.de](https://sovratis.de).

---
*Based on the open-source CIPP project by CyberDrain. For original CIPP documentation, visit [docs.cipp.app](https://docs.cipp.app).*
