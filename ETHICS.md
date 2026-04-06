# TRAIL Protocol - Ethical Principles

## Why This Document Exists

TRAIL Protocol builds identity infrastructure for AI systems. Infrastructure shapes behavior. The choices we make in protocol design determine what is easy, what is hard, and what is impossible for everyone who builds on top of TRAIL.

This document states the ethical principles that guide those choices. It is a commitment to our contributors, users, and the broader AI ecosystem.

## Core Principles

### 1. AI Must Serve Humans, Not the Other Way Around

TRAIL exists because AI systems are becoming autonomous actors in commerce, governance, and daily life. Identity infrastructure for AI must strengthen human oversight, not erode it.

**In practice, this means:**
- Every AI identity in TRAIL is linked to a verifiable human or organizational controller
- The protocol requires explicit disclosure of AI nature - no AI system should pass as human
- Human override and revocation capabilities are non-negotiable protocol features
- We design for human comprehension: trust signals must be interpretable by non-technical stakeholders

### 2. Transparency Is Non-Negotiable

Trust cannot be built on hidden mechanisms. TRAIL's trust model is based on verifiable, auditable, and publicly inspectable data.

**In practice, this means:**
- Trust Score computation is fully documented and reproducible by any verifier
- The specification is open (CC BY 4.0) and the reference implementation is open source (MIT)
- We publicly document the limitations of our trust model, not just its strengths
- Registry operations, governance decisions, and protocol changes are published with rationale

### 3. No Surveillance Infrastructure - and Dual-Use Awareness

AI identity infrastructure could be weaponized for mass surveillance, social scoring, or discriminatory profiling. We refuse to build that.

We also acknowledge that identity infrastructure is inherently dual-use. The same system that enables trust verification could be repurposed for state-controlled gatekeeping, systematic exclusion, or coercive compliance regimes. This is not a theoretical risk - it has happened with every major identity system in history. TRAIL is designed with active countermeasures against these failure modes.

**In practice, this means:**
- TRAIL uses minimal disclosure: only the information necessary for trust verification is exposed
- No behavioral tracking across contexts - a DID interaction with one verifier must not leak to another
- GDPR compliance is a design constraint, not an afterthought
- We actively reject feature requests or contributions that enable population-scale monitoring
- Correlation risk analysis is a required part of any protocol extension review
- TRAIL must never become a whitelist-only system where unregistered agents are blocked from operating. Tier 0 (self-signed) exists precisely to ensure that registration is a choice, not a precondition for existence
- Protocol design is evaluated against misuse scenarios: "How could an authoritarian actor use this feature?" is a mandatory review question for every extension proposal

### 4. Honesty About What We Are and What We Are Not

TRAIL is a trust infrastructure protocol. It is not a regulatory compliance certificate, not a safety guarantee, and not a substitute for responsible AI development.

**In practice, this means:**
- TRAIL registration does NOT constitute EU AI Act compliance - we say this explicitly in the spec
- A high Trust Score indicates verifiable identity practices, not that an AI system is safe or ethical
- We do not claim to solve AI alignment, bias, or safety - those are different problems
- Marketing and communication about TRAIL must reflect these boundaries accurately
- We support regulation like the EU AI Act not because it is mandated, but because we believe good regulation strengthens AI trust. Compliance-by-conviction, not compliance theater

### 5. Inclusive by Design

AI identity infrastructure will shape who can and who cannot deploy AI systems commercially. We design for broad access, not gatekeeping.

**In practice, this means:**
- Tier 0 (self-issued) identities work offline and cost nothing - the barrier to entry is zero
- The protocol is vendor-neutral: no single company controls who can operate a registry
- Federation is a core architectural feature, preventing monopolistic control
- We actively seek contributors from diverse geographies, industries, and technical backgrounds
- Specification language is accessible: we explain jargon and provide examples
- No protocol feature may require a specific vendor, jurisdiction, or commercial relationship to function at its base tier

### 6. Security as a Precondition for Trust

Identity infrastructure that can be forged, spoofed, or compromised destroys the trust it claims to provide. Security is not a feature - it is a precondition.

**In practice, this means:**
- Cryptographic choices are conservative and well-studied (Ed25519, JCS)
- Crypto agility is built in, with documented migration paths and deprecation windows
- We actively invite security challenges and vulnerability reports
- Key ceremony processes are documented and witnessed
- We do not deploy features that have not undergone threat modeling

## Applying These Principles

### For Contributors

These principles guide what we accept into the protocol. If a proposed feature or change conflicts with these principles, it will be rejected - regardless of its technical elegance. When in doubt, open an issue to discuss the ethical implications before investing implementation effort.

### For Registry Operators

Organizations operating TRAIL registries commit to these principles by adopting the protocol. Registry operators who violate these principles - for example, by enabling surveillance use cases or misrepresenting trust guarantees - may have their operator credentials revoked through the governance process defined in `GOVERNANCE.md`.

### For AI Agent Deployers

Registering an AI agent with TRAIL is a statement that you take identity and accountability seriously. These principles set the baseline expectation. Deployers who misuse TRAIL identity to create false trust signals undermine the ecosystem for everyone.

## Evolution

These principles are not immutable. As the AI landscape evolves, our ethical understanding must evolve with it. Changes to this document require:

1. A public proposal (GitHub Issue with the `ethics` label)
2. A minimum 30-day community review period
3. Approval by the Governance Board (or Founding Maintainer in Phase 1)
4. Publication of the rationale for any changes

We will never weaken these principles to accommodate commercial pressure. We may strengthen them as new risks emerge.

## Influences and Acknowledgments

These principles draw on:
- [OECD AI Principles](https://oecd.ai/en/ai-principles) (2019)
- [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689) - Articles 4a (AI literacy), 13 (transparency), 14 (human oversight)
- [W3C Ethical Web Principles](https://www.w3.org/TR/ethical-web-principles/)
- [Montreal Declaration for Responsible AI](https://montrealdeclaration-responsibleai.com/)
- [DIF Code of Conduct](https://github.com/decentralized-identity/org/blob/master/code-of-conduct.md)

---

*Version 1.0 - April 2026*
