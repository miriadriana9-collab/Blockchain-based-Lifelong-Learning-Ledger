# 📚 Blockchain-based Lifelong Learning Ledger

Welcome to a revolutionary platform that empowers adults in remote areas to build verifiable skill portfolios! Using the Stacks blockchain and Clarity smart contracts, this project creates an immutable ledger for lifelong learning records, solving the real-world problem of limited access to global job markets due to unverified credentials. Learners can earn, store, and showcase skills from online courses, workshops, or self-study, while employers verify them instantly without intermediaries.

## ✨ Features

📝 Register as a learner or credential issuer  
🔑 Issue tamper-proof learning credentials (e.g., certificates, badges)  
⏰ Immutable timestamps for all records  
🗂 Build and customize skill portfolios  
✅ Instant verification of credentials and portfolios  
🌍 Share portfolios securely with global employers  
🚫 Prevent fraudulent claims with hash-based uniqueness  
💼 Integration for job matching (via verifiable claims)  
🔒 Role-based access control for privacy  

## 🛠 How It Works

This project leverages 8 interconnected Clarity smart contracts to ensure security, scalability, and decentralization. Here's a high-level overview:

### Smart Contracts Overview

1. **UserRegistry.clar**: Handles registration of learners and basic user profiles. Functions: `register-user` (principal, metadata), `get-user-details`.  
2. **IssuerRegistry.clar**: Registers and verifies credential issuers (e.g., online academies). Functions: `register-issuer` (principal, name, description), `is-valid-issuer`.  
3. **CredentialIssuer.clar**: Allows registered issuers to create and issue credentials. Functions: `issue-credential` (learner-principal, hash, title, description, timestamp).  
4. **CredentialStorage.clar**: Stores credential hashes and metadata immutably. Functions: `store-credential` (id, hash, issuer, learner), `get-credential-details`.  
5. **PortfolioManager.clar**: Enables learners to curate portfolios by linking credentials. Functions: `create-portfolio` (learner, title), `add-credential-to-portfolio` (portfolio-id, credential-id).  
6. **Verification.clar**: Provides public verification tools. Functions: `verify-credential` (id, hash), `verify-portfolio-ownership` (portfolio-id, principal).  
7. **AccessControl.clar**: Manages permissions for viewing private data. Functions: `grant-access` (principal, viewer, portfolio-id), `check-access`.  
8. **DisputeResolution.clar**: Handles rare disputes over credentials (e.g., revocations). Functions: `file-dispute` (credential-id, reason), `resolve-dispute` (admin-principal, outcome).  

These contracts interact seamlessly: e.g., `CredentialIssuer` calls `CredentialStorage` to save data, and `Verification` reads from it without modifications.

**For Learners**  
- Register via `UserRegistry`.  
- Complete a course and receive a credential hash (SHA-256 of certificate PDF or data).  
- Call `add-credential-to-portfolio` in `PortfolioManager` to build your skill set.  
- Share your portfolio ID with employers for verification.  

Boom! Your skills are now globally verifiable, opening doors to remote jobs.

**For Issuers (e.g., Educators)**  
- Register in `IssuerRegistry`.  
- Use `issue-credential` to award completions, storing hashes on-chain.  

Simple and secure—no more lost certificates!

**For Verifiers (e.g., Employers)**  
- Call `verify-credential` or `verify-portfolio-ownership` to confirm authenticity.  
- Use `get-credential-details` for metadata like titles and timestamps.  

Instant trust, no paperwork.

This setup addresses accessibility in remote areas by requiring only internet access, with low-cost Stacks transactions. Future expansions could include oracle integrations for off-chain data, but it starts fully on-chain for reliability.