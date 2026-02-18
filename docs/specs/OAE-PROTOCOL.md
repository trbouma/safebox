# Offer-After-Evaluation Protocol Specification (v1.0)

## 1. Purpose
The Offer-After-Evaluation Protocol enables a provider to evaluate a request and issue a tailored offer that must be explicitly accepted before a grant is issued. This protocol ensures policy-based, conditional access to resources or services.

---

## 2. Actors

- **Requester**: Initiates a request to access a resource or service.
- **Provider**: Evaluates requests, issues offers, and grants permissions upon acceptance.

---

## 3. Protocol Flow

### 3.1 Request Submission
- The Requester submits a request to the Provider.
- Request includes:
  - Resource or service desired
  - Supporting claims or proofs (e.g., identity, intent, eligibility)
  - Optional parameters (e.g., preferences, scopes)

### 3.2 Evaluation
- The Provider evaluates the request against policy, risk, and availability.
- Evaluation may include internal logic, rules, or external verification.

### 3.3 Offer Generation
- If the evaluation is successful, the Provider generates an **Offer**.
- The Offer includes:
  - What is being offered (resource, scope, duration)
  - Conditions or constraints
  - Expiry time (optional)
  - Unique Offer ID or signature (for integrity and traceability)

### 3.4 Offer Acceptance
- The Requester explicitly accepts the Offer.
- Acceptance may include:
  - A confirmation signal or signed message
  - Consent to terms
  - Additional data, if requested (e.g., confirmation method)

### 3.5 Grant Issuance
- Upon valid acceptance, the Provider issues a **Grant**.
- The Grant represents:
  - Authorization or access token
  - Cryptographic proof or credential
  - Duration, revocation conditions, and usage scope

---

## 4. Error Handling

- If evaluation fails → `error: rejected`
- If offer is not accepted before expiry → `error: expired`
- If invalid acceptance → `error: invalid acceptance`
- If grant cannot be issued → `error: grant unavailable`

---

## 5. Security Considerations

- Offers and Grants should be signed or integrity-protected.
- Expiry and revocation mechanisms are recommended.
- Sensitive requests should be encrypted in transit.
- Replay protection for offer acceptance is advised.

---

## 6. Use Cases

- Verifiable credentials issuance  
- Delegated access authorization  
- Tiered service provisioning  
- Consent-based digital agreements
