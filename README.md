# QUIC Client – Performance Testing to emes.bj

The **QUIC Client** is a lightweight network performance testing tool that establishes bidirectional QUIC sessions with the **NDT test server** hosted at `emes.bj`.
It measures throughput and latency under different conditions, helping assess the reliability and efficiency of QUIC-based data transfers.

This client can be easily installed on **any Linux distribution** and configured to automatically run performance tests every two hours.

---

## 1. What the Client Does

Once installed, `quic-client` periodically performs upload and download tests over QUIC with the target server at **emes.bj:4447**.

Each test:

* Opens a QUIC session;
* Sends a defined amount of data to measure upload speed;
* Receives data to measure download speed;
* Logs performance results for later analysis.

---

## 2. Requirements

Before installing, make sure your system has:

```bash
sudo apt install git -y        # or dnf/yum depending on the distro
go version                     # Go must be installed manually via go.dev/doc/install
```

You must have both `git` and `go` in your `$PATH`.

---

## 3. Installation Script

Download and run the automated installation script:

```bash
curl -sSL https://raw.githubusercontent.com/liebenA/quic-client/main/scripts/install_quic_client.sh -o install_quic_client.sh
chmod +x install_quic_client.sh
./install_quic_client.sh
```

This script will:

1. Clone or update the repository from GitHub (`https://github.com/liebenA/quic-client`);
2. Run installation of `quic-client`;
3. Set up an automatic task (cron) to repeat the tests every two hours.

---

## 4. Automated Tests

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

Logs from each test run are stored in:

```
~/.quic-client/logs/
```

---

## 6. Generated Files

| Type            | Location                                |
| --------------- | --------------------------------------- |
| Compiled binary | `$(go env GOPATH)/bin/quic-client`      |
| Execution logs  | `~/.quic-client/logs/cron-YYYYMMDD.log` |
| Batch script    | `~/.local/bin/quic-client-batch.sh`     |

---

This setup is ideal for deploying on test stations or monitoring probes to continuously evaluate QUIC performance between endpoints and the `emes.bj` measurement server.
