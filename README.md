#  P2P File Sharing Network 

A fully functional **Peer-to-Peer (P2P) file sharing system** implemented in **C++** using **multithreading**, **socket programming**, and **hybrid encryption** (AES-256 + RSA). Each peer acts as both client and server, supporting secure file discovery, encrypted file transfers, and resilient chunk-based downloads — built for **scalability, modularity**, and **performance**.

---

## 📖 About

This project is a scalable and secure P2P file sharing network developed in C++. It integrates hybrid AES+RSA encryption, distributed file discovery using DFS, and optional chunked transfer with resume support — making it a robust system for learning cryptography, networking, and systems programming.

---

##  Project Features

-  **Hybrid Encryption**: RSA for secure AES key exchange, AES-256-CBC for chunk encryption (OpenSSL EVP).
-  **Multithreaded Peer**: Concurrent server-client using `std::thread`.
-  **Peer-to-Peer Architecture**: No central server; each peer communicates independently.
-  **DFS-Based File Discovery**: Distributed search using depth-first traversal over known peers.
-  **Chunked File Transfer**: Files sent/received in secure chunks.
-  **Resume Downloads**: Resume interrupted downloads using metadata logs.
-  **Modular Design**: Clean folder separation (`shared/`, `downloads/`, `metadata/`, `keys/`).
-  **Logging & UI Enhancements**: Color-coded logs, terminal-based status, clear request handling.
  
---

##  Technologies Used

- **C++17**
- **Socket Programming (POSIX)**
- **Multithreading (`std::thread`)**
- **OpenSSL - AES-256-CBC, RSA-OAEP via EVP API**
- **JSON (nlohmann/json)**
- **Filesystem (`<filesystem>` from C++17) - For file and directory management**

---

##  Project Structure

```bash
p2p_file_sharing/
│
├── downloads/         # Auto-created folder to store received files 
├── shared/            # Folder to store files available for sharing
├── keys/              # Contains RSA key pairs (excluded from Git)
├── metadata/          # Stores chunk & resume info (auto-created)(excluded from Git)
│
├── peer.cpp           # Main peer code (client-server logic, encryption, file transfer)
├── crypto_utils.cpp  # Implements AES-256 + RSA encryption/decryption
├── crypto_utils.hpp  # Crypto interface used by peer.cpp
├── peer               # Compiled binary
├── p2p_project_sample.jpeg  # Image displaying sample run of the project
│
├── Makefile           # Build instructions
├── gen_keys.sh        # 🔐 Script to generate RSA key pairs
├── run_peers.sh       # Script to launch multiple peers (ignored in Git)
├── known_peers.json   # List of known peer IPs and ports (ignored in Git)
├── json.hpp           # Single-header JSON library
└── README.md          # You are here!
```
---
##  Setup Instructions

1️⃣ Clone & Build
```bash 
git clone https://github.com/VartikaChauhan/p2p_file_sharing.git
cd p2p_file_sharing/peer
make
```

2️⃣ Generate RSA Key Pairs
(Make sure OpenSSL is installed.)
```bash 
chmod +x gen_keys.sh
./gen_keys.sh 
```
This will generate:
```bash
keys/peer1_private.pem
keys/peer1_public.pem
keys/peer2_private.pem
keys/peer2_public.pem
```

3️⃣ Add Your Peer Info
Manually or via script, update known_peers.json:
```bash 
{
  "peer1": { "ip": "x.x.x.x", "port": 5xxx },
  "peer2": { "ip": "x.x.x.x.", "port": 5xxx }
}
```

4️⃣ Run Peers
```bash
chmod +x run_peers.sh
./run_peers.sh peer1 peer2

#You'll see all peers in one tmux session, split into panes.

./peer peer1 5xxx
./peer peer2 5xxx
```
---

 ##  Sensitive Files (Excluded from Git)
These files are deliberately excluded via .gitignore:
```bash 
# .gitignore
gen_keys.sh
keys/
known_peers.json
run_peers.sh
```
---
Please regenerate keys and launch multiple peers in new terminals using the provided scripts .
### 📜 Scripts
- gen_keys.sh
```bash
#!/bin/bash

# Create keys directory if it doesn't exist
mkdir -p keys

# Check if at least one peer name is provided
if [ "$#" -lt 1 ]; then
    echo "Usage: ./gen_keys.sh peer1 [peer2 peer3 ...]"
    exit 1
fi

# Loop through all passed peer names
for PEER in "$@"; do
    echo "[*] Generating keys for $PEER..."
    openssl genpkey -algorithm RSA -out "keys/${PEER}_private.pem" -pkeyopt rsa_keygen_bits:2048
    openssl rsa -pubout -in "keys/${PEER}_private.pem" -out "keys/${PEER}_public.pem"
    echo "[✓] ${PEER}_private.pem and ${PEER}_public.pem generated."
done
```
- run_keys.sh
```bash
#!/bin/bash

SESSION_NAME="p2p_session"

# Check prerequisites
if ! command -v tmux &> /dev/null; then
    echo "[!] tmux is not installed. Please install tmux first."
    exit 1
fi

if [ ! -f ./peer ]; then
    echo "[!] 'peer' binary not found. Run 'make' first."
    exit 1
fi

if [ ! -f known_peers.json ]; then
    echo "[!] known_peers.json not found!"
    exit 1
fi

# Kill any existing tmux session with the same name
tmux kill-session -t "$SESSION_NAME" 2>/dev/null

# Start the new tmux session with the first peer
FIRST_PEER=true
for row in $(jq -r 'to_entries[] | "\(.key) \(.value.port)"' known_peers.json); do
    NAME=$(echo $row | cut -d' ' -f1)
    PORT=$(echo $row | cut -d' ' -f2)
    CMD="./peer $NAME $PORT"

    if [ "$FIRST_PEER" = true ]; then
        tmux new-session -d -s "$SESSION_NAME" "$CMD"
        FIRST_PEER=false
    else
        tmux split-window -t "$SESSION_NAME" "$CMD"
    fi
done

# Arrange panes in tiled layout and attach session
tmux select-layout -t "$SESSION_NAME" tiled
tmux attach-session -t "$SESSION_NAME"

```
---
