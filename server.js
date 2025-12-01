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
        const startOctets = startIP.split('.map(Number);
        
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
function getArpTable(logFunction) {
    const arpEntries = [];
    try {
        const fileContent = fs.readFileSync('/proc/net/arp', 'utf8');
        const lines = fileContent.split('\n');

        // Sla header over (regel 0)
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            
            // Splits de lijn op één of meer witruimtes
            const cols = line.split(/\s+/);
            
            if (cols.length >= 4) {
                const ip = cols[0];
                const mac = cols[3]; 

                if (mac && mac !== '00:00:00:00:00:00') {
                    arpEntries.push({ ip, mac });
                    logFunction(`[DEBUG: ARP OK] IP: ${ip}, MAC: ${mac}`); 
                } else {
                    logFunction(`[DEBUG: ARP SKIP] IP: ${ip} MAC is leeg of 00:00:00...`);
                }
            } else {
                 logFunction(`[DEBUG: ARP SKIP] Ongeldige kolomstructuur op regel ${i}.`);
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
            log(`Starten van parallelle ping sweep...`);

            // 1. Ping
            const pingPromises = ipList.map(ip => 
                ping.promise.probe(ip, { timeout: 1.5, extra: ['-c', '1'] })
            );

            const pingResults = await Promise.all(pingPromises);
            const aliveHosts = pingResults.filter(r => r.alive).map(r => r.host); // Alleen IP-adressen van online hosts
            log(`Ping voltooid. ${aliveHosts.length} hosts reageerden.`);

            // 2. Lees ARP (met onze eigen functie, inclusief logging)
            log(`Uitlezen ARP tabel (/proc/net/arp)...`);
            const arpTableRaw = getArpTable(log); 
            log(`${arpTableRaw.length} MAC-adressen gevonden in ARP cache (ruwe data).`);

            // 3. Filter ARP tabel en match met gescande IP's
            const arpTableFiltered = arpTableRaw.filter(entry => 
                aliveHosts.includes(entry.ip)
            );
            log(`ARP-cache gefilterd: ${arpTableFiltered.length} matches met gescande IP's.`);


            // 4. Combineer data
            results = aliveHosts.map(hostIP => {
                const arpEntry = arpTableFiltered.find(a => a.ip === hostIP);
                
                // Hostname blijft 'Unknown' 
                let hostname = 'Unknown';
                
                return {
                    ip: hostIP,
                    name: hostname,
                    mac: arpEntry ? arpEntry.mac : '??:??:??:??:??:??'
                };
            });

        } else {
            // Auto modus blijft bestaan voor backward compatibility
            log(`Geen range opgegeven, fallback modus (Kan Hostnames/MACs missen).`);
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
        log(`FATALE FOUT in scan proces: ${error.message}`);
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
