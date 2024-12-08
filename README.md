# Quantum Secure Messenger

This repository contains a simulation of a **Quantum Secure Messenger**, leveraging quantum key distribution (QKD) for secure communication and AES encryption for message confidentiality. The project demonstrates a practical implementation of quantum-resistant communication protocols.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [How It Works](#how-it-works)
6. [Requirements](#requirements)
7. [Example Scenarios](#example-scenarios)
8. [Contributing](#contributing)
9. [License](#license)

---

## Introduction

The **Quantum Secure Messenger** is a Python-based application that uses:

- **Quantum Key Distribution (QKD):** Simulates secure key exchange using quantum mechanics principles.
- **AES Encryption:** Secures messages using AES-256 encryption with a key derived from the QKD process.

This project demonstrates how quantum communication can safeguard against eavesdropping, ensuring future-proof security.

---

## Features

- **Quantum Key Distribution:** Simulates Alice, Bob, and Eve's roles in QKD.
- **Eavesdropping Detection:** Identifies when an interceptor (Eve) attempts to access the key.
- **AES Encryption:** Encrypts messages with a shared key generated from QKD.
- **Server/Client Model:** Allows communication over a TCP/IP socket connection.
- **Interactive Console:** Provides an intuitive user interface for message exchange.

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/quantum-secure-messenger.git
   cd quantum-secure-messenger
   ```

2. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt
   ```

3. Install Qiskit for quantum simulation:
   ```bash
   pip install qiskit
   ```

---

## Usage

1. **Run the Server:**
   ```bash
   python quantum_messenger.py
   ```
   Choose `server` and provide the port to listen on.

2. **Run the Client:**
   ```bash
   python quantum_messenger.py
   ```
   Choose `client`, specify the server's IP address, and provide the port.

3. Follow the prompts to:
   - Establish a quantum key.
   - Encrypt and decrypt messages securely.

---

## How It Works

1. **Quantum Key Distribution (QKD):**
   - Alice prepares qubits based on a binary message and randomly chosen bases.
   - Bob measures the qubits using randomly chosen bases.
   - Shared keys are derived from matching measurement bases.

2. **Eavesdropping Simulation:**
   - Eve intercepts qubits and measures them, introducing potential mismatches.

3. **Encryption and Communication:**
   - AES-256 encrypts messages using the derived shared key.
   - The client and server exchange encrypted messages over a socket connection.

---

## Requirements

- **Python 3.9+**
- **Libraries:**
  - `qiskit`
  - `cryptography`
  - `socket`
- **Qiskit Aer Simulator** for quantum circuit simulation.

---

## Example Scenarios

- **Successful Key Exchange:**
  - Alice and Bob agree on a shared key without interference.

- **Eavesdropping Detected:**
  - Eve intercepts qubits, causing key mismatches that terminate communication.

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add feature description"
   ```
4. Push to the branch:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request.

---


