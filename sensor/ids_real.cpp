#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include <iostream>
#include <map>
#include <string>
#include <ctime>
#include <fstream>
#include <set>
#include <sstream>
#include <iomanip>

using namespace std;

// =====================================================================
// NETGUARD SENSOR - upgraded detection engine
// Same architecture as before: capture packets -> detect patterns ->
// log locally + POST to backend. No new infrastructure, just smarter
// detection logic in this one file.
//
// UPDATE: every alert now also carries dest_ip (the packet's actual
// destination address) and a short human-readable "signature" string
// describing which rule fired - matches the class ER diagram's ALERT
// entity (DestIP, Signature columns) and lets the dashboard/DB show
// more than just source IP + event type.
//
// NOTE: Uses raw WinSock2 for the HTTP POST instead of libcurl - this
// means NO vcpkg, NO curl library needed. WinSock2 ships with Windows/
// MinGW already. Compile with: g++ ids_real.cpp -o ids_real.exe -lws2_32 -lpacket -lwpcap
// (keep whatever pcap/wpcap linker flags you were already using, just add -lws2_32)
// =====================================================================

// CHANGE THIS on demo day to the backend laptop's real IP if it's a
// separate machine, e.g. "192.168.1.50"
static const char* BACKEND_HOST = "127.0.0.1";
static const int BACKEND_PORT = 8000;

// --- Local log file (unchanged behavior) ---
ofstream logFile("ids_alerts.log");
void logAlert(const string& msg) {
    logFile << msg << endl;
    logFile.flush(); // ensure it's written immediately, useful for live demo
    cout << "\033[31m" << msg << "\033[0m" << endl;
}

// --- Sends one alert to the backend as JSON via raw WinSock2 ---
// Fire-and-forget with a short connect timeout - a dead backend must
// never slow down or block packet capture.
void sendAlertToBackend(const string& sourceIP, const string& destIP,
                         const string& eventType, const string& severity,
                         const string& message, const string& signature) {
    ostringstream json;
    json << "{"
         << "\"source_ip\":\"" << sourceIP << "\","
         << "\"dest_ip\":\"" << destIP << "\","
         << "\"event_type\":\"" << eventType << "\","
         << "\"severity\":\"" << severity << "\","
         << "\"message\":\"" << message << "\","
         << "\"signature\":\"" << signature << "\""
         << "}";
    string body = json.str();

    ostringstream request;
    request << "POST /api/alerts HTTP/1.1\r\n"
            << "Host: " << BACKEND_HOST << "\r\n"
            << "Content-Type: application/json\r\n"
            << "Content-Length: " << body.size() << "\r\n"
            << "Connection: close\r\n"
            << "\r\n"
            << body;
    string reqStr = request.str();

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return;

    // Non-blocking connect so a dead/unreachable backend can't hang the sensor
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons((u_short)BACKEND_PORT);
    inet_pton(AF_INET, BACKEND_HOST, &serverAddr.sin_addr);

    connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr));

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);
    timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 500000; // 500ms max wait

    int sel = select(0, nullptr, &writeSet, nullptr, &timeout);
    if (sel <= 0) {
        closesocket(sock); // timed out or unreachable - give up quietly
        return;
    }

    // Back to blocking briefly just to send the request
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);
    send(sock, reqStr.c_str(), (int)reqStr.size(), 0);
    closesocket(sock);
}

// Convenience: log locally AND report to backend in one call
void raiseAlert(const string& srcIP, const string& destIP, const string& eventType,
                 const string& severity, const string& humanMsg,
                 const string& backendMsg, const string& signature) {
    logAlert(humanMsg);
    sendAlertToBackend(srcIP, destIP, eventType, severity, backendMsg, signature);
}

// --- Sends a lightweight "just FYI, here's some normal traffic" sample ---
// Separate from alerts entirely - this is NOT a detection, just a heartbeat
// so the dashboard can show the sensor is alive and watching real traffic,
// not just silence between alerts.
void sendTrafficSample(const string& sourceIP, int dstPort, int bytes) {
    ostringstream json;
    json << "{"
         << "\"source_ip\":\"" << sourceIP << "\","
         << "\"dst_port\":" << dstPort << ","
         << "\"bytes\":" << bytes
         << "}";
    string body = json.str();

    ostringstream request;
    request << "POST /api/traffic HTTP/1.1\r\n"
            << "Host: " << BACKEND_HOST << "\r\n"
            << "Content-Type: application/json\r\n"
            << "Content-Length: " << body.size() << "\r\n"
            << "Connection: close\r\n"
            << "\r\n"
            << body;
    string reqStr = request.str();

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return;

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons((u_short)BACKEND_PORT);
    inet_pton(AF_INET, BACKEND_HOST, &serverAddr.sin_addr);

    connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr));

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);
    timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 300000; // shorter timeout than alerts - this is low-priority, fine to drop under load

    int sel = select(0, nullptr, &writeSet, nullptr, &timeout);
    if (sel <= 0) {
        closesocket(sock);
        return;
    }

    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);
    send(sock, reqStr.c_str(), (int)reqStr.size(), 0);
    closesocket(sock);
}

// =====================================================================
// Tracking state - one map per detection rule, all keyed by source IP
// =====================================================================

// RULE: Port scan (unique destination ports contacted quickly)
map<string, set<int>> uniquePorts;
map<string, time_t> portScanWindowStart;

// RULE: SYN flood (many half-open connection attempts)
map<string, int> synCount;
map<string, time_t> synWindowStart;

// RULE: ICMP ping sweep / flood
map<string, int> icmpCount;
map<string, time_t> icmpWindowStart;

// RULE: Brute-force on admin ports (repeated hits on the SAME port)
map<string, int> adminPortHits; // key = srcIP + ":" + port
map<string, time_t> adminPortWindowStart;

// RULE: Anomalous packet size - learned per-source baseline (EMA), not a
// fixed threshold. This is anomaly-based detection: compare current
// behavior to that specific source's own learned "normal", rather than
// matching a fixed signature.
map<string, double> avgPacketSize;    // running baseline per source IP
map<string, int> packetSampleCount;   // how many packets we've learned from, per source IP

// Generic per-rule alert cooldown, key = srcIP + "_" + ruleName
map<string, time_t> lastAlertTime;
bool cooldownOk(const string& key, time_t now, int cooldownSeconds) {
    if (now - lastAlertTime[key] >= cooldownSeconds) {
        lastAlertTime[key] = now;
        return true;
    }
    return false;
}

// Static blacklist - fill this in with real known-bad IPs before your
// demo if you have any (e.g. an attacker VM's fixed IP). Empty by default.
set<string> blacklistedIPs = {
    // "10.0.0.99",
};

// =====================================================================
// Tunable thresholds - adjust here if your demo triggers too easily or
// not easily enough
// =====================================================================
static const int PORTSCAN_WINDOW_SECONDS   = 10;
static const int PORTSCAN_THRESHOLD        = 20;   // unique ports in window

static const int SYN_WINDOW_SECONDS        = 5;
static const int SYN_FLOOD_THRESHOLD       = 30;   // SYN packets in window

static const int ICMP_WINDOW_SECONDS       = 5;
static const int ICMP_FLOOD_THRESHOLD      = 15;   // ICMP echo requests in window

static const int ADMIN_PORT_WINDOW_SECONDS = 15;
static const int BRUTEFORCE_THRESHOLD      = 5;    // repeated hits on same admin port

static const int ALERT_COOLDOWN_SECONDS    = 10;   // shared cooldown per rule per IP

static const int LARGE_PACKET_COOLDOWN_SECONDS = 60;   // quieter than other rules, this one is noisy by nature

// --- Anomaly-based detection tunables (baseline learning, not a fixed rule) ---
static const double BASELINE_EMA_ALPHA   = 0.1;   // weight given to each new sample (lower = slower/smoother baseline)
static const int    BASELINE_MIN_SAMPLES = 20;    // packets needed before we trust a source's baseline enough to judge it
static const double ANOMALY_MULTIPLIER   = 5.0;   // flag if packet is 5x this source's own average size
static const int    ANOMALY_FLOOR_BYTES  = 2000;  // absolute floor - stops a tiny baseline from triggering trivially

static const set<int> ADMIN_PORTS = {22, 23, 3389};

// =====================================================================
// Packet handler - called by Npcap for every captured packet
// =====================================================================
void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    const u_char* ipHeader = packet + 14; // skip Ethernet header

    int version = (ipHeader[0] >> 4) & 0x0F;
    if (version != 4) return; // IPv4 only

    string srcIP = to_string(ipHeader[12]) + "." +
                   to_string(ipHeader[13]) + "." +
                   to_string(ipHeader[14]) + "." +
                   to_string(ipHeader[15]);

   
    string dstIP = to_string(ipHeader[16]) + "." +
                   to_string(ipHeader[17]) + "." +
                   to_string(ipHeader[18]) + "." +
                   to_string(ipHeader[19]);

    time_t now = time(nullptr);

    
    if (blacklistedIPs.count(srcIP)) {
        string key = srcIP + "_blacklist";
        if (cooldownOk(key, now, ALERT_COOLDOWN_SECONDS)) {
            raiseAlert(srcIP, dstIP, "blacklisted_ip", "high",
                "[ALERT] Traffic from BLACKLISTED IP: " + srcIP,
                "Known malicious source contacted this host",
                "Blacklisted Source IP Match");
        }
    }

    int protocol = ipHeader[9];
    int ipHeaderLen = (ipHeader[0] & 0x0F) * 4;
    const u_char* payload = ipHeader + ipHeaderLen;

    // -----------------------------------------------------------------
    // ICMP (protocol 1) - ping sweep / flood detection
    // No ports exist on ICMP, so this is handled completely separately.
    // -----------------------------------------------------------------
    if (protocol == 1) {
        int icmpType = payload[0];
        if (icmpType == 8) { // Echo Request
            if (icmpWindowStart[srcIP] == 0) icmpWindowStart[srcIP] = now;
            if (now - icmpWindowStart[srcIP] > ICMP_WINDOW_SECONDS) {
                icmpCount[srcIP] = 0;
                icmpWindowStart[srcIP] = now;
            }
            icmpCount[srcIP]++;

            if (icmpCount[srcIP] >= ICMP_FLOOD_THRESHOLD) {
                string key = srcIP + "_icmp";
                if (cooldownOk(key, now, ALERT_COOLDOWN_SECONDS)) {
                    raiseAlert(srcIP, dstIP, "icmp_flood", "medium",
                        "[ALERT] Possible PING SWEEP/FLOOD from " + srcIP +
                        " (" + to_string(icmpCount[srcIP]) + " echo requests in " +
                        to_string(ICMP_WINDOW_SECONDS) + "s)",
                        to_string(icmpCount[srcIP]) + " ICMP echo requests in " +
                        to_string(ICMP_WINDOW_SECONDS) + "s",
                        "ICMP Echo Flood Threshold Exceeded");
                }
            }
        }
        return; // nothing more to do for ICMP
    }

    // Only TCP(6) or UDP(17) proceed past this point
    if (protocol != 6 && protocol != 17) return;

    const u_char* tcpUDP = payload;
    int srcPort = (tcpUDP[0] << 8) + tcpUDP[1];
    int dstPort = (tcpUDP[2] << 8) + tcpUDP[3];

    // -----------------------------------------------------------------
    // TCP-only: flags-based stealth scan detection + SYN flood
    // -----------------------------------------------------------------
    if (protocol == 6) {
        u_char flags = tcpUDP[13];
        bool FIN = flags & 0x01;
        bool SYN = flags & 0x02;
        bool RST = flags & 0x04;
        bool PSH = flags & 0x08;
        bool ACK = flags & 0x10;
        bool URG = flags & 0x20;

        // NULL scan: no flags set at all
        if (flags == 0x00) {
            string key = srcIP + "_nullscan";
            if (cooldownOk(key, now, ALERT_COOLDOWN_SECONDS)) {
                raiseAlert(srcIP, dstIP, "stealth_scan_null", "high",
                    "[ALERT] NULL scan detected from " + srcIP + " -> Port " + to_string(dstPort),
                    "TCP packet with no flags set (NULL scan) targeting port " + to_string(dstPort),
                    "TCP NULL Scan Pattern");
            }
        }
        // FIN scan: only FIN set
        else if (flags == 0x01) {
            string key = srcIP + "_finscan";
            if (cooldownOk(key, now, ALERT_COOLDOWN_SECONDS)) {
                raiseAlert(srcIP, dstIP, "stealth_scan_fin", "high",
                    "[ALERT] FIN scan detected from " + srcIP + " -> Port " + to_string(dstPort),
                    "TCP packet with only FIN flag set targeting port " + to_string(dstPort),
                    "TCP FIN Scan Pattern");
            }
        }
        // XMAS scan: FIN + PSH + URG set together
        else if (FIN && PSH && URG) {
            string key = srcIP + "_xmasscan";
            if (cooldownOk(key, now, ALERT_COOLDOWN_SECONDS)) {
                raiseAlert(srcIP, dstIP, "stealth_scan_xmas", "high",
                    "[ALERT] XMAS scan detected from " + srcIP + " -> Port " + to_string(dstPort),
                    "TCP packet with FIN+PSH+URG flags (XMAS scan) targeting port " + to_string(dstPort),
                    "TCP XMAS Scan Pattern (FIN+PSH+URG)");
            }
        }

        // SYN flood tracking: SYN set, ACK not set = connection attempt, not established traffic
        if (SYN && !ACK) {
            if (synWindowStart[srcIP] == 0) synWindowStart[srcIP] = now;
            if (now - synWindowStart[srcIP] > SYN_WINDOW_SECONDS) {
                synCount[srcIP] = 0;
                synWindowStart[srcIP] = now;
            }
            synCount[srcIP]++;

            if (synCount[srcIP] >= SYN_FLOOD_THRESHOLD) {
                string key = srcIP + "_synflood";
                if (cooldownOk(key, now, ALERT_COOLDOWN_SECONDS)) {
                    raiseAlert(srcIP, dstIP, "syn_flood", "high",
                        "[ALERT] Possible SYN FLOOD from " + srcIP +
                        " (" + to_string(synCount[srcIP]) + " SYNs in " +
                        to_string(SYN_WINDOW_SECONDS) + "s)",
                        to_string(synCount[srcIP]) + " half-open connection attempts in " +
                        to_string(SYN_WINDOW_SECONDS) + "s",
                        "SYN Flood Threshold Exceeded");
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // RULE: Admin port access + brute-force escalation
    // First touch = simple notice. Repeated hits on the same admin port
    // from the same IP within the window = brute-force alert.
    // -----------------------------------------------------------------
    if (ADMIN_PORTS.count(dstPort)) {
        string portKey = srcIP + ":" + to_string(dstPort);

        if (adminPortWindowStart[portKey] == 0) adminPortWindowStart[portKey] = now;
        if (now - adminPortWindowStart[portKey] > ADMIN_PORT_WINDOW_SECONDS) {
            adminPortHits[portKey] = 0;
            adminPortWindowStart[portKey] = now;
        }
        adminPortHits[portKey]++;

        if (adminPortHits[portKey] == 1) {
            // first touch - low severity notice
            raiseAlert(srcIP, dstIP, "admin_port_access", "medium",
                "[ALERT] Suspicious port access: IP=" + srcIP + " -> Port=" + to_string(dstPort),
                "First access attempt on port " + to_string(dstPort),
                "Admin Port Access Attempt");
        }
        else if (adminPortHits[portKey] >= BRUTEFORCE_THRESHOLD) {
            string key = portKey + "_bruteforce";
            if (cooldownOk(key, now, ALERT_COOLDOWN_SECONDS)) {
                raiseAlert(srcIP, dstIP, "brute_force_admin", "high",
                    "[ALERT] Possible BRUTE FORCE from " + srcIP + " on port " +
                    to_string(dstPort) + " (" + to_string(adminPortHits[portKey]) +
                    " attempts in " + to_string(ADMIN_PORT_WINDOW_SECONDS) + "s)",
                    to_string(adminPortHits[portKey]) + " repeated connection attempts on port " +
                    to_string(dstPort),
                    "Repeated Admin Port Access - Brute Force Pattern");
            }
        }
    }

    // -----------------------------------------------------------------
    // RULE: Port scan (unique ports touched quickly)
    // -----------------------------------------------------------------
    if (portScanWindowStart[srcIP] == 0) portScanWindowStart[srcIP] = now;
    if (now - portScanWindowStart[srcIP] > PORTSCAN_WINDOW_SECONDS) {
        uniquePorts[srcIP].clear();
        portScanWindowStart[srcIP] = now;
    }
    uniquePorts[srcIP].insert(dstPort);

    if ((int)uniquePorts[srcIP].size() >= PORTSCAN_THRESHOLD) {
        string key = srcIP + "_portscan";
        if (cooldownOk(key, now, ALERT_COOLDOWN_SECONDS)) {
            raiseAlert(srcIP, dstIP, "port_scan", "high",
                "[ALERT] Possible PORT SCAN by " + srcIP +
                " (unique ports in " + to_string(PORTSCAN_WINDOW_SECONDS) +
                "s = " + to_string(uniquePorts[srcIP].size()) + ")",
                to_string(uniquePorts[srcIP].size()) + " unique ports in " +
                to_string(PORTSCAN_WINDOW_SECONDS) + "s",
                "Port Scan - Unique Port Threshold Exceeded");
        }
    }

    // -----------------------------------------------------------------
    // RULE: DNS tunneling heuristic (abnormally large DNS packets)
    // -----------------------------------------------------------------
    if (protocol == 17 && (srcPort == 53 || dstPort == 53) && header->len > 512) {
        string key = srcIP + "_dnstunnel";
        if (cooldownOk(key, now, ALERT_COOLDOWN_SECONDS)) {
            raiseAlert(srcIP, dstIP, "dns_tunneling", "medium",
                "[ALERT] Abnormally large DNS packet from " + srcIP +
                " (" + to_string(header->len) + " bytes) - possible tunneling",
                to_string(header->len) + " byte DNS packet (possible tunneling)",
                "Abnormal DNS Packet Size - Tunneling Heuristic");
        }
    }

    // -----------------------------------------------------------------
    // RULE: Anomalous packet size (ANOMALY-BASED, not signature-based)
    //
    // Every other rule in this file is signature-based: it matches a
    // known, fixed pattern (a specific flag combo, a fixed port, a fixed
    // count in a fixed window). This rule works differently - it LEARNS
    // each source IP's typical packet size over its first N packets,
    // then only alerts when a later packet is dramatically larger than
    // that specific source's own normal pattern. This is why a real
    // 8000-byte packet from a source that normally sends 8000-byte
    // packets is NOT flagged, but a 3000-byte packet from a source that
    // normally sends 200-byte packets IS - the anomaly is relative, not
    // absolute.
    // -----------------------------------------------------------------
    {
        int pktLen = (int)header->len;

        if (packetSampleCount[srcIP] < BASELINE_MIN_SAMPLES) {
            // Still learning this source's normal behavior. Don't judge
            // yet - alerting before the baseline is trustworthy would
            // just be a fixed-threshold rule wearing a costume.
            packetSampleCount[srcIP]++;
            avgPacketSize[srcIP] = (avgPacketSize[srcIP] == 0.0)
                ? (double)pktLen
                : (avgPacketSize[srcIP] * (packetSampleCount[srcIP] - 1) + pktLen) / packetSampleCount[srcIP];
        } else {
            double baseline = avgPacketSize[srcIP];

            if (pktLen > ANOMALY_FLOOR_BYTES && pktLen > baseline * ANOMALY_MULTIPLIER) {
                string key = srcIP + "_largepacket";
                if (cooldownOk(key, now, LARGE_PACKET_COOLDOWN_SECONDS)) {
                    ostringstream ratio;
                    ratio << fixed << setprecision(1) << (pktLen / baseline);
                    raiseAlert(srcIP, dstIP, "large_packet", "low",
                        "[ALERT] Anomalous packet size from " + srcIP + ": " + to_string(pktLen) +
                        " bytes (" + ratio.str() + "x this source's normal baseline of " +
                        to_string((int)baseline) + " bytes)",
                        to_string(pktLen) + " bytes - " + ratio.str() + "x above baseline (" +
                        to_string((int)baseline) + " byte avg for this source)",
                        "Packet Size Anomaly - EMA Baseline Deviation");
                }
            }

            // Update the baseline using an Exponential Moving Average -
            // gives more weight to recent traffic while still smoothing
            // out single-packet spikes, so genuine sustained behavior
            // change (e.g. this device starts a video call) shifts the
            // baseline over time instead of triggering forever.
            avgPacketSize[srcIP] = BASELINE_EMA_ALPHA * pktLen + (1 - BASELINE_EMA_ALPHA) * baseline;
        }
    }

    // Occasional normal traffic line so you know the sensor is alive
    if (rand() % 50 == 0) {
        cout << "\033[32mNormal traffic: " << srcIP
             << " -> Port " << dstPort
             << " (" << header->len << " bytes)\033[0m" << endl;
        sendTrafficSample(srcIP, dstPort, (int)header->len);
    }
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed - alerts won't reach the backend, but sensor will still run and log locally.\n";
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;
    cout << "=== NETGUARD Sensor (Windows + Npcap) ===\n";
    cout << "Detection rules active: port scan, SYN flood, ICMP flood,\n";
    cout << "stealth scans (NULL/FIN/XMAS), admin port brute-force,\n";
    cout << "DNS tunneling heuristic, large packets, IP blacklist.\n\n";

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
        cerr << "Error finding devices: " << errbuf << endl;
        WSACleanup();
        return 1;
    }

    cout << "Available Network Interfaces:\n";
    int idx = 0;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        cout << "[" << idx << "] " << d->name;
        if (d->description) cout << " | " << d->description;
        cout << endl;
        idx++;
    }

    cout << "\nSelect interface number (try Wi-Fi/Ethernet): ";
    int choice = 0;
    cin >> choice;

    pcap_if_t* device = alldevs;
    for (int i = 0; i < choice && device != nullptr; i++) device = device->next;

    if (!device) {
        cerr << "Invalid selection.\n";
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    cout << "\nUsing interface: " << device->name << endl;
    if (device->description) cout << "Description: " << device->description << endl;

    pcap_t* handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);

    if (!handle) {
        cerr << "Could not open device: " << errbuf << endl;
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    pcap_freealldevs(alldevs);

    cout << "\nNETGUARD sensor started! Press CTRL+C to stop.\n";
    cout << "Logging alerts to: ids_alerts.log\n";
    cout << "Reporting alerts to: http://localhost:8000/api/alerts\n\n";

    pcap_loop(handle, 0, packetHandler, NULL);

    pcap_close(handle);
    WSACleanup();
    return 0;
}
