from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
import random
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket

# Quantum Key Distribution Functions
def alice_prepares_qubits(binary_message):  
    """
    Alice prepares qubits based on the binary message.
    Each qubit's state is determined by a randomly chosen basis and the message bit.
    """
    qubits_info = []
    circuits = []
    for bit in binary_message:
        basis = random.choice([0, 1])  # Randomly choose a basis (0 = Z-basis, 1 = X-basis)
        bit = int(bit)

        # Create the quantum circuit
        qc = QuantumCircuit(1, 1)
        if bit == 1:
            qc.x(0)  # Apply X-gate if the bit is 1
        if basis == 1:
            qc.h(0)  # Apply Hadamard if basis is X-basis
        circuits.append(qc)
        qubits_info.append((basis, bit))
    return circuits, qubits_info

def eve_intercepts_qubits(circuits):
    """
    Eve intercepts the qubits, measures them in a random basis, and then resends them.
    Eve does not know Alice's or Bob's chosen bases, causing potential mismatches.
    """
    simulator = AerSimulator()
    eve_results = []
    intercepted_circuits = []
    
    for circuit in circuits:
        eve_basis = random.choice([0, 1])  # Eve measures in a random basis
        if eve_basis == 1:
            circuit.h(0)  # Apply Hadamard if Eve uses X-basis
        circuit.measure(0, 0)  # Measure the qubit
        result = simulator.run(circuit).result()
        counts = result.get_counts()
        measured_bit = int(list(counts.keys())[0])  # Extract the measured bit
        eve_results.append((eve_basis, measured_bit))
        
        # After measuring, Eve prepares the qubit to resend it to Bob
        if eve_basis == 1:
            circuit.h(0)  # Apply Hadamard if she measured in X-basis
        intercepted_circuits.append(circuit)  # Send it to Bob
    return intercepted_circuits, eve_results

def bob_measures_qubits(circuits):
    """
    Bob measures the received qubits in a randomly chosen basis.
    """
    simulator = AerSimulator()
    bob_results = []
    for circuit in circuits:
        bob_basis = random.choice([0, 1])  # Randomly choose a measurement basis
        if bob_basis == 1:
            circuit.h(0)  # Apply Hadamard if Bob uses X-basis
        circuit.measure(0, 0)  # Measure the qubit
        result = simulator.run(circuit).result()
        counts = result.get_counts()
        measured_bit = int(list(counts.keys())[0])  # Extract the measured bit
        bob_results.append((bob_basis, measured_bit))
    return bob_results

def generate_shared_key(alice_info, bob_info):
    """
    Generate a shared key by comparing Alice's and Bob's bases.
    Only bits where the bases match are included in the key.
    """
    shared_key = []
    for (alice_basis, alice_bit), (bob_basis, bob_bit) in zip(alice_info, bob_info):
        if alice_basis == bob_basis:
            shared_key.append(alice_bit)
    return ''.join(map(str, shared_key))

# Utility Functions
def text_to_binary(text):
    """
    Convert a plaintext message to binary.
    """
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary_message):
    """
    Convert a binary string back to plaintext.
    """
    chars = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)

# AES Encryption and Decryption Functions
def pad_key(key, desired_length=32):
    """
    Pad the shared key to the desired length using SHA-256 hash if it is too short.
    """
    if len(key) < desired_length * 8:  # The key length is in bits, so multiply desired length by 8
        key = key.ljust(desired_length * 8, '0')  # Pad with '0' to the desired length
    return key[:desired_length * 8]  # Truncate or pad to the required length

def aes_encrypt(plaintext, key):
    """
    Encrypt the plaintext using AES encryption with the shared key.
    """
    # Ensure the key is the correct size (e.g., 32 bytes for AES-256)
    key = pad_key(key)  # Pad or truncate the key
    key_bytes = bytes(int(key[i:i+8], 2) for i in range(0, len(key), 8))  # Convert binary to bytes
    iv = os.urandom(16)  # Generate a random Initialization Vector (16 bytes)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv, ciphertext

def aes_decrypt(iv, ciphertext, key):
    """
    Decrypt the ciphertext using AES decryption with the shared key.
    """
    # Ensure the key is the correct size (e.g., 32 bytes for AES-256)
    key = pad_key(key)  # Pad or truncate the key
    key_bytes = bytes(int(key[i:i+8], 2) for i in range(0, len(key), 8))  # Convert binary to bytes
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')  # Ensure UTF-8 decoding

# Network Communication Functions
def start_server(port):
    """
    Start the server for receiving and responding to messages securely.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(("", port))
        server_socket.listen(1)
        print(f"Server started and listening on port {port}...")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")
            # Receive the shared key from the client
            shared_key = conn.recv(1024).decode()
            print(f"Server received shared key: {shared_key}")

            while True:
                # Receive Alice's message
                data = conn.recv(1024)
                if not data:
                    break

                # Split IV and ciphertext
                iv, ciphertext = data[:16], data[16:]

                # Decrypt the message
                print(f"The Encrypted Message received is:{ciphertext}")
                decrypted_message = aes_decrypt(iv, ciphertext, shared_key)
                print(f"Server: Received and Decrypted Message: {decrypted_message}")

                # If "exit" is sent, close the connection
                if decrypted_message.lower() == "exit":
                    print("Connection closed by client.")
                    break

                # Send a reply message back to Alice
                reply_message = input("Server: Enter your reply message: ")
                iv_reply, ciphertext_reply = aes_encrypt(reply_message, shared_key)
                conn.sendall(iv_reply + ciphertext_reply)
                print(f"Server: Sent Encrypted Reply: {ciphertext_reply}")

def start_client(host, port):
    """
    Start the client for sending and receiving messages securely.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print(f"Connected to server at {host}:{port}")

        # Perform quantum key distribution and send the shared key
        print("Establishing Quantum Secure Connection...")

        # Generate a random binary message for key generation
        binary_message = ''.join(random.choice(['0', '1']) for _ in range(8))  # 8-bit example message

        # Alice prepares qubits
        alice_circuits, alice_info = alice_prepares_qubits(binary_message)

        # Ask user if Eve should intercept the qubits
        eve_intercept_choice = input("Should Eve intercept the qubits? (yes/no): ").strip().lower()

        if eve_intercept_choice == "yes":
            # Eve intercepts the qubits
            intercepted_circuits, eve_info = eve_intercepts_qubits(alice_circuits)
            print(f"Eve's measured bits: {eve_info}")
            print("Key mismatch detected. Terminating communication due to Eve's interference.")
            client_socket.sendall("Key mismatch detected".encode())
            return
        else:
            # Alice directly sends the qubits to Bob
            intercepted_circuits = alice_circuits
            eve_info = []

        # Bob measures the intercepted qubits
        bob_info = bob_measures_qubits(intercepted_circuits)

        # Generate shared key (after eavesdropping)
        shared_key = generate_shared_key(alice_info, bob_info)
        print(f"Client (Alice) generated shared key: {shared_key}")
        print(f"Eve's measured bits: {eve_info}")


        # Send the shared key to the server
        client_socket.sendall(shared_key.encode())

        while True:
            # Get Alice's message to send
            plaintext = input("\nClient: Enter your message (or 'exit' to quit): ")

            # Encrypt the message
            iv, ciphertext = aes_encrypt(plaintext, shared_key)

            # Send IV and ciphertext
            client_socket.sendall(iv + ciphertext)
            print(f"Client: Encrypted Message Sent: {ciphertext}")

            if plaintext.lower() == "exit":
                print("Connection closed.")
                break

            # Receive and decrypt server's response
            data = client_socket.recv(1024)
            iv_reply, ciphertext_reply = data[:16], data[16:]
            print(f"Encrypted Reply is:{ciphertext_reply}")
            decrypted_reply = aes_decrypt(iv_reply, ciphertext_reply, shared_key)
            print(f"Client: Decrypted Reply: {decrypted_reply}")

def quantum_messenger(role, port=None, host=None):
    """
    Simulate a secure messenger using quantum key exchange.
    """
    if role == "client":
        start_client(host, port)

    elif role == "server":
        start_server(port)
    else:
        print("Invalid role. Please choose 'server' or 'client'.")

# Main function to run the messenger
if __name__ == "__main__":
    role = input("Choose your role ('server' or 'client'): ").strip().lower()

    if role == "server":
        port = int(input("Enter the port to listen on: "))
        quantum_messenger(role, port=port)

    elif role == "client":
        host = input("Enter the server address: ").strip()
        port = int(input("Enter the server port: "))
        quantum_messenger(role, host=host, port=port)
    else:
        print("Invalid role. Please choose 'server' or 'client'.")
