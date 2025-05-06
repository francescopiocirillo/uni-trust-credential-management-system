🔐 Uni-Trust: Decentralized Academic Credential System
=====================================================

> 🚀 A privacy-preserving, decentralized system for managing academic credentials, built for international student mobility programs like Erasmus. Designed with a modular architecture and security-first principles as part of a university project.

* * *

📌 Overview
-----------

**Uni-Trust** is a secure and interoperable system for issuing, selectively disclosing, and revoking **academic credentials**. It was developed as part of a team project for a graduate-level security engineering course, and reflects a real-world design and development workflow with strong emphasis on **privacy**, **verifiability**, and **cross-border compatibility**.

### 📁 Project Highlights

* ✅ Verifiable credentials based on W3C standards  
* 🧠 Selective disclosure using cryptographic proofs  
* 🔄 Decentralized Identifiers (DIDs) for identity management  
* 🚫 Revocable and non-transferable credential issuance  
* 📊 Formal threat model and security analysis  
* 🧪 Prototype with performance evaluation  
* 📌 Focus on constrained devices (e.g., smartphones)

* * *

🌍 Language Note
----------------

All internal documentation and diagrams are written in **Italian**, as the project was developed during a group exam at the **University of Salerno (Italy)**.

However, all code, protocol specifications, and technical elements are written following **international best practices**, and are understandable by developers worldwide.

* * *

💡 Features
-----------

### 🎓 Credential Lifecycle

* Credential issuance by an authorized university  
* Verifiable presentation to another institution  
* Selective attribute disclosure  
* Efficient revocation support  

### 🛡️ Security Properties

* Integrity and authenticity via digital signatures  
* Privacy via selective disclosure and unlinkability  
* Resistance to forgery, replay attacks, and identity theft  
* Local-first architecture to minimize external dependencies  

### 📶 Interoperability

* Based on **W3C Verifiable Credentials** and **DIDs**  
* Suitable for integration with existing identity ecosystems  
* No centralized trust anchor required  

* * *

🧠 Development Process
----------------------

> Developed over 8 weeks as a capstone project, following a milestone-based plan with parallel task assignments.

1. ✅ **Modeling & Requirement Analysis**  
2. 🔐 **Threat Modeling & Security Objectives**  
3. 🧱 **Protocol Design & System Architecture**  
4. 💻 **Proof-of-concept Implementation**  
5. 📊 **Performance Evaluation**  
6. 📄 **Final Documentation and Presentation**  

Each team member was responsible for two distinct work packages (WPs).

* * *

🧪 Testing & Evaluation
------------------------

Although the system is not a production-grade tool, a simulated **proof-of-concept** was built to evaluate:

* Credential size on constrained devices  
* Verification latency  
* Cryptographic overhead  
* Revocation mechanisms  

Results and benchmarks are available in the `WP4_Implementation/results/` folder.

* * *

📋 Documentation
----------------

You can find full documentation in the `docs/` folder, including:

* **Threat Model** – Adversary capabilities and system resilience  
* **Architecture & Protocol Diagrams** – Credential lifecycle and message flows  
* **Security Analysis** – Formal reasoning against defined attacks  
* **User Scenarios** – Example flows for Erasmus student credential usage  
* **Work Package Reports** – Breakdown of individual contributions  

* * *

🧱 Project Structure
--------------------

```
📦 uni-trust
├── 📁 WP1_Model
│   └── System model, actors, properties, and threat model
├── 📁 WP2_Design
│   └── System and protocol design (diagrams + pseudocode)
├── 📁 WP3_SecurityAnalysis
│   └── Security properties and formal analysis
├── 📁 WP4_Implementation
│   ├── Prototype code and scripts
│   └── Performance analysis results
├── 📁 docs
│   └── Final report, presentation slides, diagrams
└── README.md
```

* * *

🧑‍💻 Team – University of Salerno
---------------------------------

* [@francescopiocirillo]#https://github.com/francescopiocirillo
* [@alefaso-lucky](#https://github.com/alefaso-lucky)

* * *

🚀 How to Run the Prototype
----------------------------

1. Clone the repo:

   ```bash
   git clone https://github.com/your-org/uni-trust.git
   cd uni-trust/WP4_Implementation/
   ```

2. Follow the instructions in the `README.md` inside the implementation folder to run the simulation.

### 🧩 Development Environment

- 💻 Python 3.x
- 🔐 Cryptographic library: to be defined
- 📦 VC/DID libraries: to be defined

* * *

📬 Contacts
-----------

Have questions, suggestions, or want to collaborate?  
Feel free to contribute or open an **issue** on GitHub!

* * *

📈 SEO Tags
-----------

```
Decentralized Credential System, Academic Verifiable Credentials, Erasmus Credential Sharing, DID VC System, W3C Verifiable Credentials, Privacy-Preserving Identity, Student Identity Blockchain, Credential Revocation, Secure University Credential System, Identity Wallet for Education, Cross-Border Credential System, Secure Credential Verification, Zero Knowledge Credentials, Decentralized Identity for Students, Italian University Software Project, Privacy in Academic Mobility
```

* * *

📄 License
----------

This project is licensed under the **MIT License**, a permissive open-source license that allows anyone to use, modify, and distribute the software freely — as long as credit is given and the original license is included.

> In plain terms: **use it, build on it, just don’t blame us if something breaks**.

> ⭐ Like what you see? Consider giving the project a star!

* * *
