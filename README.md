# 🔗 P2P File Sharing Network 

A fully functional **Peer-to-Peer (P2P) file sharing system** implemented in **C++** using **multithreading**, **socket programming**, and **hybrid encryption** (AES-256 + RSA). Each peer acts as both client and server, supporting secure file discovery, encrypted file transfers, and resilient chunk-based downloads — built for **scalability, modularity**, and **performance**.

---

## 📦 Project Features

- 🔐 **Hybrid Encryption**: AES-256 for data, RSA for key exchange (using OpenSSL).
- 🧵 **Multithreaded**: Server and clients operate on separate threads.
- 🕸️ **P2P Architecture**: No centralized control; distributed peer discovery using DFS.
- 🔎 **Secure File Search**: Depth-First Search across peers to locate files.
- 🧠 **Modular Design**: Separated shared/downloads/keys/metadata folders.
- ♻️ **Resume Support** *(optional extension)*: For interrupted downloads.
- ✅ **Chunked File Transfer** *(optional extension)*

---

## 🛠️ Technologies Used

- **C++17**
- **Socket Programming (POSIX)**
- **Multithreading (`std::thread`)**
- **OpenSSL (AES-256-CBC, RSA-OAEP)**
- **JSON (nlohmann/json)**
- **Filesystem (`<filesystem>` from C++17)**

---

## 🗂️ Project Structure

```bash
p2p_file_sharing/
│
├── downloads/         # Auto-created folder to store received files 
├── shared/            # Folder to store files available for sharing
├── keys/              # Contains public.pem & private.pem (ignored in Git)
│
├── peer.cpp           # Main peer code (client-server logic, encryption, file transfer)
├── peer               # Compiled binary 
├── Makefile           # Build file
├── run_peers.sh       # Script to launch multiple peers
├── gen_keys.sh        # 🔐 Script to generate RSA key pairs (ignored in Git)
├── known_peers.json   # 🔗 List of known peers and ports (ignored in Git)
├── json.hpp           # Single-header JSON library (nlohmann)
└── README.md          # You are here!
```
---
## 🔧 Setup Instructions

- 1️⃣ Clone & Build
```bash 
git clone https://github.com/VartikaChauhan/p2p_file_sharing.git
cd p2p_file_sharing/peer
make
```

- 2️⃣ Generate RSA Key Pairs
(Make sure OpenSSL is installed.)
```bash 
chmod +x gen_keys.sh
./gen_keys.sh
```
This will generate:
```bash
keys/public.pem
keys/private.pem
```

- 3️⃣ Add Your Peer Info
Manually or via script, update known_peers.json:
```bash 
{
  "peer1": { "ip": "x.x.x.x", "port": 5xxx },
  "peer2": { "ip": "x.x.x.x.", "port": 5xxx }
}
```

- 4️⃣ Run Peers
```bash
./peer peer1 5xxx
./peer peer2 5xxx
```
---

- ##🚫 Sensitive Files (Excluded from Git)
These files are deliberately excluded via .gitignore:
```bash 
# .gitignore
gen_keys.sh
keys/
known_peers.json
```
Please regenerate keys and peer lists locally using provided scripts.
---

- ##📬 Usage
From terminal after starting a peer:
```bash 
Enter filename to download (or 'exit' to quit): example.pdf
```
Peers will search and fetch the file securely from other peers and save to downloads/.
