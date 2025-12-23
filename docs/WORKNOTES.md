# Working Notes
Capture of rough notes for documentation

## Offer Accept Sequence
This is the process of offering a record to another Safebox holder

## Generic Offer-Grant Scheme
Each offer-grant pair is a replaceable pair of event of kind `3XXXXX`, where `3XXXXX` is an odd number, and the corresponding grant is the next sequence, an even number. For example for a Badge, the offer kind is `34001` and the grant kind is `34002`. 

An implementation is free to decide what kinds they wish to use so long as the kinds are `34000 <= n 40000` which are addressable events defined by `kind`, `pubkey` and `d-tag`. As per NIP-01 only the latest event is stored.

If a `d-tag` is not specified `default` will be used. Please note that safe box derives a hashed version of `default` so it is not cannot be correlated or inferred by an outside observer.

## Sequence
There are two roles in this sequence: An `offeror` and an `acceptor`.

An `offeror` creates an offer of records (may be multiple records, if so desired)

## 🜂 Uniform Conveyance Model (UCM)
*The transfer of intent, value, or record.*

Generic pattern for transfer for title/non-title records

| Phase | Step | Role | Verb | Description |
|--------|------|------|------|-------------|
| **Invocation** | 1 | **Grantor** | **Create** | The Grantor formulates an offer — a declaration of intent and initial terms. Note: Depending on the capabilities of the grantor/grantee, the offer may be presented as a QR code that is scanned by the grantee. Alternaatively, the grantor might acquire a grantee token (via reading a NFC card, for example) and communicate via another channel.|
| **Invocation** | 2 | **Grantee** | **Consider** | The Grantee reviews and interprets the offer; may assess conditions or propose adjustments. |
| **Invocation** | 3 | **Grantee** | **Confirm** | The Grantee finalizes and signals alignment of terms, establishing mutual understanding. |
| **Invocation** | 4 | **Grantor** | **Convey** | The Grantor transfers or delivers the agreed value, title, or record — activating the exchange. |
| **Evocation** | 5 | **Grantee** | **Receive** | The Grantee obtains what has been conveyed — initiating realization. |
| **Evocation** | 6 | **Grantee** | **Review** | The Grantee verifies authenticity, integrity, and completeness of the received item. |
| **Evocation** | 7 | **Both** | **Recognize** | Both parties acknowledge fulfillment; the exchange is accepted as valid and complete. |
| **Evocation** | 8 | **System / Ledger** | **Record** | The transaction is attested or anchored as an enduring fact — finalizing the conveyance. |

---

### Summary
> **Create → Consider → Confirm → Convey → Receive → Review → Recognize → Record**

This eight-step cycle defines the canonical pattern of lawful and verifiable exchange within the **Uniform architecture**, bridging **intent** and **proof** through reciprocal, attestable interaction.


# Complete table

# 🕊️ Uniform Conveyance Model Across Eight Domains

| **Phase** | **Step** | **Core Function** | **Publication**<br>*(Publisher → Consumer)* | **Record of Attestation**<br>*(Attestor → Subject)* | **Credential Issuance**<br>*(Issuer → Holder)* | **Payment (E-Cash)**<br>*(Payer → Payee)* | **Trade Document (Bill of Lading)**<br>*(Carrier → Consignee)* | **Prescription**<br>*(Physician → Patient / Pharmacist)* | **Land Title Transfer**<br>*(Seller → Buyer; Registry)* | **Professional License**<br>*(Regulator → Practitioner)* |
|------------|-----------|------------------|---------------------------------|---------------------------------|-----------------------------------------------|-------------------------------------------|-------------------------------------------------------------|-------------------------------------------------------------|-------------------------------------------------------------|-------------------------------------------------------------|
| **Invocation** | **1. Create** | Expression of *lawful intent* to communicate, attest, or transfer a right. | Publisher authors or issues a note — intent to communicate or disclose. | Attestor creates record declaring fact (e.g., birth, audit, certification). | Issuer defines credential offer — intent to confer attested authority. | Payer formulates payment offer or transaction intent. | Carrier issues bill of lading — intent to convey title to goods. | Physician formulates prescription — intent to authorize treatment. | Seller drafts deed — intent to convey land title. | Regulator prepares license grant — intent to confer professional authority. |
| | **2. Consider** | *Evaluation or acknowledgment before acceptance.* | Consumer chooses to read or access content; evaluates source or relevance. | Subject or representative reviews or acknowledges the attested facts. | Holder reviews credential offer. | Payee reviews payment conditions. | Consignee reviews shipment terms. | Patient reviews treatment plan. | Buyer reviews title and deed. | Applicant reviews eligibility. |
| | **3. Confirm** | *Mutual consent or acknowledgment to proceed.* | Consumer consents (subscribe, agree to terms, engage). | Subject confirms participation or provides evidence for attestation. | Holder consents to issuance and provides data. | Payee confirms readiness to receive. | Consignee accepts terms. | Patient provides informed consent. | Buyer and seller execute contract. | Applicant confirms compliance and submits application. |
| | **4. Convey** | *Conveyance — issuance or transmission of an attested record, value, or right.* | Publisher releases information publicly or to subscriber. | Attestor issues signed record to subject (certificate, report, affidavit). | Issuer signs and delivers credential. | Payer transmits token or payment proof. | Carrier transfers control of e-BoL. | Physician signs and sends prescription. | Seller delivers deed. | Regulator issues signed license. |
| **Evocation** | **5. Receive** | *Possession or control of conveyed object or record.* | Consumer accesses content. | Subject receives attested record (birth certificate, audit report). | Holder receives credential in wallet. | Payee receives token or funds. | Consignee gains control of e-BoL. | Pharmacist receives prescription. | Buyer receives deed. | Practitioner receives license. |
| | **6. Review** | *Verification of authenticity and integrity.* | Consumer interprets or verifies message. | Subject or third party verifies record authenticity and integrity. | Holder verifies credential signature. | Payee validates payment authenticity. | Holder verifies document’s integrity. | Pharmacist verifies prescription authenticity. | Buyer verifies deed validity. | Employer verifies license validity. |
| | **7. Recognize** | *Mutual recognition or acknowledgment of legal or evidentiary effect.* | Reader acknowledges or cites message. | Both attestor and subject recognize record as true and valid; may be witnessed or registered. | Issuer and holder acknowledge credential validity. | Payer and payee acknowledge settlement. | Carrier and consignee recognize title transfer. | All parties acknowledge authorization. | Buyer and seller recognize completion. | Regulator and practitioner acknowledge lawful status. |
| | **8. Record** | *Durable evidence or registration ensuring persistence and trust.* | Publication archived or timestamped. | Record entered in registry or archive (vital records, audit log, blockchain). | Credential anchored in registry. | Ledger logs transaction. | Registry logs transfer. | EHR logs prescription issuance. | Land registry records title. | Licensing registry updates status. |


# ⚖️ Uniform Conveyance Model — Summary Table (Five Core Domains)

| **Phase** | **Step** | **Core Function** | **Publication**<br>*(Publisher → Consumer)* | **Record of Attestation**<br>*(Attestor → Subject)* | **Credential Issuance**<br>*(Issuer → Holder)* | **Payment (E-Cash)**<br>*(Payer → Payee)* | **Land Title Transfer**<br>*(Seller → Buyer; Registry)* |
|------------|-----------|------------------|---------------------------------|---------------------------------|-----------------------------------------------|-------------------------------------------|-------------------------------------------------------------|
| **Invocation** | **1. Create** | Expression of *lawful intent* to communicate, attest, or transfer a right. | Publisher authors or issues a message or post. | Attestor creates record declaring fact (e.g., birth, audit). | Issuer defines credential offer — intent to confer authority. | Payer formulates payment or transfer intent. | Seller drafts deed — intent to convey land title. |
| | **2. Consider** | *Evaluation or acknowledgment before acceptance.* | Consumer evaluates or chooses to access information. | Subject reviews or acknowledges facts. | Holder reviews credential offer. | Payee reviews payment conditions. | Buyer reviews title and deed. |
| | **3. Confirm** | *Mutual consent or acknowledgment to proceed.* | Consumer subscribes or agrees to terms. | Subject confirms participation or provides data. | Holder consents to issuance and provides data. | Payee confirms readiness to receive. | Buyer and seller execute contract. |
| | **4. Convey** | *Issuance or transmission of the record, value, or right.* | Publisher releases or posts information. | Attestor issues signed record or certificate. | Issuer signs and delivers credential. | Payer transmits token or payment proof. | Seller delivers deed of transfer. |
| **Evocation** | **5. Receive** | *Possession or control of conveyed object or record.* | Consumer accesses or downloads content. | Subject receives attested record. | Holder receives credential. | Payee receives token or funds. | Buyer receives deed. |
| | **6. Review** | *Verification of authenticity and integrity.* | Consumer verifies or interprets content. | Subject or third party verifies authenticity. | Holder verifies credential signature. | Payee validates payment authenticity. | Buyer verifies deed validity. |
| | **7. Recognize** | *Mutual recognition or acknowledgment of effect.* | Reader acknowledges or cites message. | Attestor and subject recognize record as valid. | Issuer and holder acknowledge credential validity. | Payer and payee acknowledge settlement. | Buyer and seller recognize title transfer. |
| | **8. Record** | *Durable registration ensuring persistence and trust.* | Publication archived or timestamped. | Record entered in registry or archive. | Credential anchored in registry. | Ledger logs transaction. | Land registry records ownership. |



🕊️ Summary of the Uniform Conveyance Model (UCM)

The Uniform Conveyance Model (UCM) describes the universal sequence by which any lawful act of transfer occurs — whether the transfer concerns information, authority, value, title, or ownership.
At its core, the UCM treats every transaction as a structured process of lawful conveyance that unfolds through eight recurring stages:
Create, Consider, Confirm, Convey, Receive, Review, Recognize, and Record.

These eight steps represent the full lifecycle of trust and evidence that underlies every exchange between a grantor (the originator or issuer) and a grantee (the recipient or subject).
Each step corresponds to a legal or procedural milestone: the expression of intent, evaluation of terms, mutual consent, formal act of conveyance, receipt of the conveyed object, verification of authenticity, mutual recognition of effect, and finally recordation in a trusted register or system of record.

By abstracting these stages from specific domains, the UCM provides a common legal grammar that can be applied across radically different contexts.
A publisher releasing information, a registrar attesting a fact, a university issuing a credential, a payer transferring digital value, a carrier endorsing a bill of lading, a physician writing a prescription, a seller conveying land, or a regulator granting a professional license — all are performing the same fundamental act of conveyance.
They differ only in what is being conveyed (expression, attestation, authority, value, title, or permission) and in the medium by which that conveyance is recorded (ledger, registry, database, or blockchain).

The model reveals that lawful exchange is a communicative and evidentiary process, not merely a technical or contractual one.
Every valid conveyance requires intent, consent, authenticity, recognition, and durable evidence.
The UCM unifies these elements into a single interoperable structure that can describe both traditional legal transactions (deeds, licenses, certificates) and digital interactions (credentials, tokens, payments, or verifiable records).

In essence, the Uniform Conveyance Model offers a way to harmonize diverse systems of law, governance, and technology under one coherent lifecycle of trust.
It enables consistent reasoning across domains — bridging contract and property law, evidence and communication theory, and the emerging architectures of digital trust and identity.
By grounding all exchanges in a common structure of lawful conveyance, the UCM establishes a conceptual foundation for a Uniform Law of Lawful Transfers in the digital era.

