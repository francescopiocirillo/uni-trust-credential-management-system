🔐 Uni-Trust: Decentralized Academic Credential System
=====================================================

🚀 A **decentralized academic credential sharing system** with **selective disclosure** and **revocation support**, implemented using **Merkle Trees**, **blockchain-based revocation lists**, and **secure key exchange protocols**. Designed and developed as part of a university project for the _Algorithms and Protocols for Security_ course.

> Demonstrated ability to design and implement secure, privacy-preserving credential management systems using cryptographic protocols, blockchain-based revocation, and Merkle Tree–based selective disclosure.

* * *

📌 Overview
-----------

**Uni-Trust** is a **secure academic credential management system** enabling **students, universities, and certification authorities** to exchange credentials in a **privacy-preserving**, **verifiable**, and **revocable** manner.

This project was developed at the **University of Salerno** as a practical application of cryptographic techniques to improve **student mobility programs** such as Erasmus, reducing reliance on centralized authorities and improving **trust** and **interoperability** between institutions.

### 📁 Project Highlights

* ✅ **Selective disclosure** of academic credentials using **Merkle Trees**
    
* 🔐 **Decentralized revocation management** via **blockchain-based Certificate Revocation Lists (CRLs)**
    
* 🔑 **Mutual authentication** and **secure key distribution protocols** to establish session keys
    
* 🧾 **Rich credential structure** supporting personal data, courses, exams, degrees, and attendance records
    
* 📊 **Performance analysis** on credential size, cryptographic overhead, and latency
    
* 🧪 **Threat modeling** and **security analysis** covering common attack vectors
    

* * *

🌍 Language Note
----------------

All **code comments and internal documentation** are written in **Italian**, as the project was developed during a group exam at the **University of Salerno (Italy)**.

Despite this, the **codebase follows international best practices**, with clear method names and class structures that make it easily understandable for global developers and recruiters.

* * *

💡 Features
-----------

### 🧾 Credential Management

* **Issuance** of academic credentials by universities
    
* **Selective disclosure** of only necessary fields (e.g., specific course completions)
    
* **Verifiable Merkle proofs** for disclosed credentials
    

### 🔐 Security & Privacy

* **RSA asymmetric encryption** for identity validation and signing
    
* **AES symmetric encryption** for session communication
    
* **Secure key distribution protocol** using nonces and identity verification
    
* **Blockchain-based revocation** of credentials to ensure real-time trust
    

### 🧮 Advanced Capabilities

* **Merkle Tree–based credential structure** enabling partial disclosure without exposing full datasets
    
* **Revocation List (CRL)** management on a decentralized blockchain (the blockchain interaction is simulated as it was beyond the scope of the project)
    
* **Resilience to attacks** like man-in-the-middle, identity theft, and credential tampering
    

* * *

🧠 Development Process
----------------------

> Developed within a structured **university project framework** (Project Work), with clearly defined **work packages** for modeling, design, security analysis, and implementation.

1. **Requirements Analysis & Threat Modeling** (WP1)
    
2. **System Design**: Credential structure, secure exchange, revocation handling (WP2)
    
3. **Security Analysis**: Evaluation against defined adversary models (WP3)
    
4. **Implementation**: Modular Python code with cryptographic best practices (WP4)
    

* * *

🧪 Testing
----------

The system has been tested with:

* **Unit tests** for encryption/decryption, Merkle Tree verification, and proof generation
    
* **Simulated communication workflows** between students and universities
    
* **Latency and overhead analysis** for cryptographic operations
    

* * *

📋 Documentation
----------------

Inside the `docs/` folder, you’ll find:

* **Requirements & Threat Model Report**: Identifies key actors, goals, and attack vectors
    
* **System Design Document**: Describes credential structures, data flows, and protocols
    
* **Security Analysis Report**: Evaluates resilience against identified threats
    
* **Performance Evaluation**: Overhead and latency benchmarks

All these information are contained in the file `Documentazione_APS_gruppo06_Cirillo_Fasolino.pdf`
    

* * *

🧱 Project Structure
--------------------

```
📦 uni-trust-credential-management-system
├── 📁 docs
│   ├── project_presentation_ITALIAN.pdf
│   ├── project_report_ENGLISH.pdf
│   └── project_report_ITALIAN.pdf
├── 📁 src
│   ├── 📁 actors
│   │   ├── Blockchain.py
│   │   ├── CertifiedCommunicatingParty.py
│   │   ├── Student.py
│   │   ├── StudentInfo.py
│   │   ├── University.py
│   │   └── __init__.py
│   ├── 📁 certificate_authority
│   │   ├── CertificateAuthority.py
│   │   ├── CertificateOfIdentity.py
│   │   └── __init__.py
│   ├── 📁 utils
│   │   ├── AsymmetricEncryptionInformation.py
│   │   ├── CryptoUtils.py
│   │   ├── MerkleTree.py
│   │   ├── SymmetricEncryptionInformation.py
│   │   ├── __init__.py
│   │   └── __init__.py
│   ├── main_documentato.ipynb
│   └── main.py
├── LICENSE
├── README.md
└── requirements.txt
```

* * *

📸 System Overview Snapshot
---------------------------

<img width="1724" height="968" alt="image" src="https://github.com/user-attachments/assets/5ea3cb39-696e-4209-bbff-7f7b58c5a0e5" />

* * *

🚀 How to Run Locally
---------------------

1. Clone the repository
    
    ```bash
    git clone https://github.com/francescopiocirillo/uni-trust-credential-management-system.git
    ```
    
2. Install dependencies
    
    ```bash
    pip install -r requirements.txt
    ```
    
3. Run the simulation notebook
    
    ```bash
    jupyter notebook main_documentato.ipynb
    ```
    

### 🧩 Development Environment

* 🐍 Python version: **3.12+**
    
* 🔐 Cryptography library: **cryptography**
    
* 🪙 Blockchain simulation through a simple class for revocation list
    

* * *

📬 Contacts
-----------

✉️ Got feedback or want to contribute? Feel free to open an Issue or submit a Pull Request!

* * *

📈 SEO Tags
-----------

```
Decentralized Credential Management, Academic Credentials, Merkle Tree Credentials, Blockchain Revocation, Selective Disclosure, Privacy-Preserving Credentials, Secure Key Exchange Protocol, RSA & AES Encryption, Python Cryptography Project, Erasmus Credential Sharing, Certificate Revocation List Blockchain, Secure University Data Exchange, Project Work Algorithms and Protocols for Security, Cryptography-Based Credential System, Merkle Proof Verification, Student Credential Privacy, University of Salerno Project
```

* * *

📄 License
----------

This project is licensed under the **MIT License**, a permissive open-source license that allows anyone to use, modify, and distribute the software freely, as long as credit is given and the original license is included.

> In plain terms: **use it, build on it, just don’t blame us if something breaks**.

> ⭐ Like what you see? Consider giving the project a star!

* * *
