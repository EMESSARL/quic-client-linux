# QUIC Client – Performance Testing to emes.bj

The **QUIC Client** is a lightweight network performance testing tool that establishes QUIC sessions with the test server hosted at **emes.bj**.  
It measures throughput and multi-stream performance under different load conditions, helping assess QUIC reliability and efficiency.

This client can be easily installed on **any Linux distribution** and on **macOS (Intel & Apple Silicon)**.  
Once installed, it automatically runs performance tests every two hours using a scheduled cron job.

---

## 1. What the Client Does

Once installed, `quic-client` periodically performs QUIC upload tests with the target server at **emes.bj:4447**.

Each test:

* Opens a QUIC session  
* Sends data across multiple streams  
* Measures upload throughput  
* Logs detailed performance metrics for later analysis  

---

## 2. Installation Script

Download and run the automated installation script (as root):

```bash
curl -sSL https://raw.githubusercontent.com/liebenA/quic-client-linux/main/scripts/install_quic_client.sh -o install_quic_client.sh
chmod +x install_quic_client.sh
sudo ./install_quic_client.sh
```

This script will:

1. Clone or update the repository from GitHub (`https://github.com/liebenA/quic-client-linux`);
2. Run installation of `quic-client`;
3. Set up an automatic task (cron) to repeat the tests every two hours.

---

## 3. Automated Tests

After installation, and every two hours, the following tests are executed sequentially:

```bash
quic-client -u emes.bj -p 4447 -n 1  -d 65536
quic-client -u emes.bj -p 4447 -n 5  -d 262144
quic-client -u emes.bj -p 4447 -n 30 -d 262144
```

These parameters represent:

* `-u` → target server hostname (`emes.bj`);
* `-p` → port number (default: `4447`);
* `-n` → number of data streams;
* `-d` → data payload size per stream (in bytes).

---

## 4. Generated Files

| Type              | Location                                      |
| ------------------|-----------------------------------------------|
| Compiled binary   | `/usr/local/bin/quic-client`                  |
| Execution logs    | `/var/log/quic-client/cron-YYYYMMDD_HHMM.log` |
| Batch script      | `/usr/local/bin/quic-client-batch.sh`         |
| Source directory  | `/opt/quic-client`                            |   

---

