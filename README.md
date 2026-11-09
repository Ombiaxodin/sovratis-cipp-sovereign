
![Sovratis Light](github_assets/img/sovratis-Light.png#gh-light-mode-only)
![Sovratis Dark](github_assets/img/Sovratis.png#gh-dark-mode-only)

# Sovratis Sovereign Cloud Manager (Based on CIPP)

## What is the Sovereign Cloud Manager?

The Sovratis Sovereign Cloud Manager is an enterprise-grade modification of the CyberDrain Improved Partner Portal (CIPP). The standard CIPP assumes all tenants operate within the Global Microsoft 365 environment.

This assumption fails in **Sovereign Clouds** (e.g., the German DELOS Cloud) where API endpoints and capabilities differ fundamentally.

To solve this, **Sovratis Consulting** is extending the CIPP core to natively support multi-cloud routing and strict data sovereignty requirements for enterprise and municipal data centers.

## Phase 1 Objectives

We are currently focusing exclusively on the following two core architectural changes:

### 1. Dynamic Sovereign Cloud Routing

- **Tenant Configuration Extension:** The tenant onboarding model is expanded to include a cloud environment selector (`Global` vs. `DELOS`).
- **Dynamic API Endpoints:** Instead of hardcoded Microsoft Graph and Exchange endpoints, central request wrappers dynamically route API calls to the correct regional endpoints based on the tenant's configured environment.

### 2. Double Key Encryption (DKE) & HSM Integration

- **Absolute Data Protection:** Securing all sensitive customer and tenant data stored in Azure.
- **HSM Integration:** Implementing a Double Key Encryption pattern utilizing an HSM module in Azure. This ensures that sensitive configurations, tokens, and credentials are encrypted at the application level before being committed to any Azure database or storage account.

## Intellectual Property & Maintainer

Designed and maintained by **Sovratis Consulting** – Specialized in B2B IT Security, Enterprise Cloud Architecture, and Sovereign Data Protection.

For enterprise licensing or Sovereign Cloud consulting, visit [sovratis.de](https://sovratis.de).

---

*Based on the open-source CIPP project by CyberDrain. For original CIPP documentation, visit [docs.cipp.app](https://docs.cipp.app).*
