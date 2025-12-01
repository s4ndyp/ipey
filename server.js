const express = require('express');
const cors = require('cors');
const ping = require('ping');
const fs = require('fs'); // Nodig om direct ARP tabel te lezen

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// --- Helper: IP Range Parser ---
function parseIPRange(rangeStr) {
    const ips = [];
    try {
        if (!rangeStr.includes('-')) return [rangeStr];
        const parts = rangeStr.split('-');
        const startIP = parts[0];
        const endPart = parts[1];
        const startOctets = startIP.split('.').map(Number);
        
        let endLastOctet = endPart.includes('.') ? parseInt(endPart.split('.')[3]) : parseInt(endPart);

        for (let i = startOctets[3]; i <= endLastOctet; i++) {
            ips.push(`${startOctets[0]}.${startOctets[1]}.${startOctets[2]}.${i}`);
        }
    } catch (e) {
        console.error("Parse error:", e);
    }
    return ips;
}

// --- Helper: Handmatige ARP Lezer (Linux/Docker) ---
// Dit lost het probleem op dat 'local-devices' soms faalt in containers.
function getArpTable() {
    const arpEntries = [];
    try {
        // Lees direct de kernel ARP tabel
        const fileContent = fs.readFileSync('/proc/net/arp', 'utf8');
        const lines = fileContent.split('\n');

        // Sla header over (regel 0)
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            
            // Regex om IP en MAC te pakken. 
            // Formaat: IP address (0) | HW type (1) | Flags (2) | HW address (3) ...
            const cols = line.split(/\s+/);
            if (cols.length >= 4) {
                const ip = cols[0];
                const mac = cols[3];
                // Filter incomplete entries (00:00:00...)
                if (mac !== '00:00:00:00:00:00') {
                    arpEntries.push({ ip, mac });
                }
            }
        }
    } catch (e) {
        console.error("Kan /proc/net/arp niet lezen:", e);
    }
    return arpEntries;
}

// --- API: SCAN ---
app.get('/api/scan', async (req, res) => {
    // We houden een logboek bij om terug te sturen naar de frontend
    const sessionLogs = [];
    function log(msg) {
        console.log(msg); // Toon in Docker logs
        sessionLogs.push(`[Server] ${msg}`); // Voeg toe aan response
    }

    try {
        const scanRange = req.query.subnet;
        log(`Scan verzoek voor: ${scanRange || 'Auto'}`);

        let results = [];

        if (scanRange && scanRange.includes('-')) {
            const ipList = parseIPRange(scanRange);
            log(`Range berekend: ${ipList.length} adressen.`);
            log(`Starten van parallelle ping sweep...`);

            // 1. Ping
            const pingPromises = ipList.map(ip => 
                ping.promise.probe(ip, { timeout: 1.5, extra: ['-c', '1'] })
            );

            const pingResults = await Promise.all(pingPromises);
            const aliveHosts = pingResults.filter(r => r.alive);
            log(`Ping voltooid. ${aliveHosts.length} hosts reageerden.`);

            // 2. Lees ARP (Nu met onze eigen robuuste functie)
            log(`Uitlezen ARP tabel (/proc/net/arp)...`);
            const arpTable = getArpTable();
            log(`${arpTable.length} items in ARP cache gevonden.`);

            // 3. Match
            results = aliveHosts.map(host => {
                const arpEntry = arpTable.find(a => a.ip === host.host);
                
                // Hostname resolutie is lastig in Docker zonder DNS setup.
                // We geven nu een standaard naam terug of proberen te kijken of 'ping' iets teruggaf.
                let hostname = 'Unknown';
                if (host.host === '127.0.0.1') hostname = 'localhost';
                
                return {
                    ip: host.host,
                    name: hostname,
                    mac: arpEntry ? arpEntry.mac : '??:??:??:??:??:??'
                };
            });

        } else {
            // Auto modus blijft bestaan voor backward compatibility
            log(`Geen range opgegeven, fallback modus.`);
            const find = require('local-devices');
            results = await find();
        }

        log(`Scan sessie afgerond. ${results.length} resultaten.`);
        
        res.json({
            success: true,
            logs: sessionLogs, // We sturen de logs mee terug!
            devices: results
        });

    } catch (error) {
        log(`FATALE FOUT: ${error.message}`);
        res.status(500).json({ success: false, logs: sessionLogs, message: error.message });
    }
});

// --- API: PING ---
app.post('/api/ping', async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ success: false });

    try {
        const resPing = await ping.promise.probe(ip, { timeout: 2 });
        res.json({
            success: true,
            alive: resPing.alive,
            time: resPing.time
        });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.listen(PORT, () => {
    console.log(`Backend server draait op http://localhost:${PORT}`);
});
