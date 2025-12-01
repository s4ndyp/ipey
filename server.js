const express = require('express');
const cors = require('cors');
const ping = require('ping');
const { exec } = require('child_process'); 

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

// --- Helper: Debug Netwerk Info ---
// Voert 'ifconfig' uit om te zien in welke netwerk-omgeving we draaien
function checkNetworkInterface(logFunction) {
    return new Promise((resolve) => {
        exec('ifconfig', (error, stdout, stderr) => {
            if (error) {
                logFunction(`[NET CHECK] Kan ifconfig niet draaien.`);
                return resolve();
            }
            // Log alleen de regels met 'inet ' om IP's te tonen
            const ipLines = stdout.split('\n').filter(l => l.includes('inet ')).map(l => l.trim());
            logFunction(`[NET CHECK] Huidige container IP's: ${ipLines.join(' | ')}`);
            resolve();
        });
    });
}

// --- Helper: Shell ARP Lezer ---
function getArpTableFromShell(logFunction) {
    return new Promise((resolve) => {
        exec('cat /proc/net/arp', (error, stdout, stderr) => {
            if (error) {
                logFunction(`[SHELL ERROR] Kon cat niet uitvoeren: ${error.message}`);
                return resolve([]);
            }

            logFunction(`[DEBUG RAW] ARP bestand grootte: ${stdout.length} chars`);

            const arpEntries = [];
            const lines = stdout.split('\n');
            
            // Regexes
            const macRegex = /([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/;
            const ipRegex = /(\d{1,3}\.){3}\d{1,3}/;

            for (let i = 1; i < lines.length; i++) {
                const line = lines[i].trim();
                if (!line) continue;

                const ipMatch = line.match(ipRegex);
                const macMatch = line.match(macRegex);

                if (ipMatch && macMatch) {
                    const ip = ipMatch[0];
                    const mac = macMatch[0];

                    if (mac !== '00:00:00:00:00:00') {
                        arpEntries.push({ ip, mac });
                    }
                }
            }
            resolve(arpEntries);
        });
    });
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

        // STAP 0: Check netwerk omgeving
        await checkNetworkInterface(log);

        let results = [];

        if (scanRange && scanRange.includes('-')) {
            const ipList = parseIPRange(scanRange);
            log(`Range: ${ipList.length} adressen.`);
            
            // 1. Ping
            const pingPromises = ipList.map(ip => 
                ping.promise.probe(ip, { timeout: 1.5, extra: ['-c', '1'] })
            );

            const pingResults = await Promise.all(pingPromises);
            const aliveHosts = pingResults.filter(r => r.alive).map(r => r.host);
            log(`Ping voltooid. ${aliveHosts.length} hosts online.`);

            // 2. Lees ARP via SHELL
            log(`Uitlezen ARP via shell...`);
            const arpTableRaw = await getArpTableFromShell(log);
            log(`${arpTableRaw.length} MAC-adressen gevonden.`);

            // 3. Match
            results = aliveHosts.map(hostIP => {
                const arpEntry = arpTableRaw.find(a => a.ip === hostIP);
                return {
                    ip: hostIP,
                    name: 'Unknown',
                    mac: arpEntry ? arpEntry.mac : '??:??:??:??:??:??'
                };
            });

        } else {
            const find = require('local-devices'); 
            results = await find(scanRange || null);
        }

        log(`Scan klaar. ${results.length} resultaten.`);
        
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
