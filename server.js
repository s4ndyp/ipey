const express = require('express');
const cors = require('cors');
const find = require('local-devices');
const ping = require('ping');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Helper: Maak een lijst van IP's uit een range string
// Ondersteunt formaten zoals "192.168.1.1-50" en "192.168.1.1-192.168.1.50"
function parseIPRange(rangeStr) {
    const ips = [];
    try {
        if (!rangeStr.includes('-')) return [rangeStr];

        const parts = rangeStr.split('-');
        const startIP = parts[0];
        const endPart = parts[1];

        const startOctets = startIP.split('.').map(Number);
        
        // Bepaal eindnummer (handelt '...1.1-50' en '...1.1-192.168.1.50' af)
        let endLastOctet = 0;
        if (endPart.includes('.')) {
            endLastOctet = parseInt(endPart.split('.')[3]);
        } else {
            endLastOctet = parseInt(endPart);
        }

        // Genereer IP lijst (alleen voor laatste octet ranges voor nu)
        for (let i = startOctets[3]; i <= endLastOctet; i++) {
            ips.push(`${startOctets[0]}.${startOctets[1]}.${startOctets[2]}.${i}`);
        }
    } catch (e) {
        console.error("Parse error:", e);
    }
    return ips;
}

// --- API: SCAN ---
app.get('/api/scan', async (req, res) => {
    try {
        const scanRange = req.query.subnet;
        console.log(`[SCAN] Start: ${scanRange || 'Auto'}`);

        let results = [];

        if (scanRange && scanRange.includes('-')) {
            // --- SNELLE MODUS: Parallel Pingen ---
            const ipList = parseIPRange(scanRange);
            console.log(`[SCAN] ${ipList.length} IP's pingen...`);

            // 1. Ping alles tegelijk (Promise.all) voor maximale snelheid
            // We pingen met een korte timeout (1s) omdat we er veel tegelijk doen.
            // '-c 1' zorgt dat er maar 1 packet verstuurd wordt.
            const pingPromises = ipList.map(ip => 
                ping.promise.probe(ip, { timeout: 1, extra: ['-c', '1'] })
            );

            const pingResults = await Promise.all(pingPromises);
            
            // Filter alleen de apparaten die online zijn
            const aliveHosts = pingResults.filter(r => r.alive);
            console.log(`[SCAN] Ping klaar. ${aliveHosts.length} hosts online.`);

            // 2. Haal ARP data op (nu de ARP cache gevuld is door de pings)
            // Dit koppelt MAC adressen aan de gevonden IP's
            const arpTable = await find();

            // 3. Combineer data
            results = aliveHosts.map(host => {
                // Zoek MAC in ARP tabel
                const arpEntry = arpTable.find(a => a.ip === host.host);
                return {
                    ip: host.host,
                    // Gebruik ARP naam of 'Unknown'
                    name: arpEntry ? arpEntry.name : 'Unknown', 
                    // Gebruik ARP mac of een placeholder zodat hij tenminste in de lijst komt
                    mac: arpEntry ? arpEntry.mac : '??:??:??:??:??:??' 
                };
            });

        } else {
            // --- AUTO MODUS (local-devices standaard) ---
            // Voor als er geen specifieke range wordt opgegeven
            results = await find(scanRange || null);
        }

        console.log(`[SCAN] Klaar. ${results.length} resultaten verstuurd.`);
        
        res.json({
            success: true,
            devices: results
        });

    } catch (error) {
        console.error('[SCAN] Error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// --- API: PING ---
// Endpoint voor het pingen van een enkel IP adres
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
