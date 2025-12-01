const express = require('express');
const cors = require('cors');
const ping = require('ping');
const fs = require('fs'); 

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
        
        // Split correct afsluiten en mappen
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

// --- Helper: Robuuste ARP Lezer (Regex based) ---
function getArpTable(logFunction) {
    const arpEntries = [];
    try {
        const fileContent = fs.readFileSync('/proc/net/arp', 'utf8');
        const lines = fileContent.split('\n');

        // Regex om een MAC adres te vinden (6 groepen van 2 hex karakters gescheiden door :)
        const macRegex = /([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/;
        // Regex om een IP adres te vinden (simpele versie)
        const ipRegex = /(\d{1,3}\.){3}\d{1,3}/;

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            
            // In plaats van kolommen tellen, zoeken we patronen
            const ipMatch = line.match(ipRegex);
            const macMatch = line.match(macRegex);

            if (ipMatch && macMatch) {
                const ip = ipMatch[0];
                const mac = macMatch[0];

                // Filter ongeldige MACs
                if (mac !== '00:00:00:00:00:00') {
                    arpEntries.push({ ip, mac });
                    // Loggen dat we hem gevonden hebben
                    logFunction(`[DEBUG: PARSED] IP: ${ip} -> MAC: ${mac}`);
                }
            }
        }
    } catch (e) {
        logFunction(`FATALE FOUT bij lezen /proc/net/arp: ${e.message}`);
    }
    return arpEntries;
}

// --- API: SCAN ---
app.get('/api/scan', async (req, res) => {
    const sessionLogs = [];
    function log(msg) {
        const time = new Date().toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        console.log(`[${time}] ${msg}`); 
        sessionLogs.push(`[${time}] ${msg}`); 
    }

    try {
        const scanRange = req.query.subnet;
        log(`Scan verzoek voor: ${scanRange || 'Auto'}`);

        let results = [];

        if (scanRange && scanRange.includes('-')) {
            const ipList = parseIPRange(scanRange);
            log(`Range berekend: ${ipList.length} adressen.`);
            
            // 1. Ping
            const pingPromises = ipList.map(ip => 
                ping.promise.probe(ip, { timeout: 1.5, extra: ['-c', '1'] })
            );

            const pingResults = await Promise.all(pingPromises);
            const aliveHosts = pingResults.filter(r => r.alive).map(r => r.host);
            log(`Ping voltooid. ${aliveHosts.length} hosts reageerden.`);

            // 2. Lees ARP (met Regex parser)
            log(`Uitlezen ARP tabel...`);
            const arpTableRaw = getArpTable(log); 
            log(`${arpTableRaw.length} MAC-adressen succesvol geparsed.`);

            // 3. Match
            // We zoeken in de geparsede tabel naar het IP.
            results = aliveHosts.map(hostIP => {
                // Zoek exacte match
                const arpEntry = arpTableRaw.find(a => a.ip === hostIP);
                
                return {
                    ip: hostIP,
                    name: 'Unknown',
                    mac: arpEntry ? arpEntry.mac : '??:??:??:??:??:??'
                };
            });

        } else {
            // Fallback
            const find = require('local-devices'); 
            results = await find(scanRange || null);
        }

        log(`Scan sessie afgerond. ${results.length} resultaten.`);
        
        res.json({
            success: true,
            logs: sessionLogs, 
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
