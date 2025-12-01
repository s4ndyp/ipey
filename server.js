const express = require('express');
const cors = require('cors');
const find = require('local-devices');
const ping = require('ping');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());

// --- API: SCAN ---
// Route om het netwerk te scannen. Gebruikt de 'subnet' query parameter.
app.get('/api/scan', async (req, res) => {
    try {
        // Lees de 'subnet' parameter uit de URL (bijv. ?subnet=192.168.1.1-255)
        const scanRange = req.query.subnet || null;
        console.log(`[SCAN] Start op range: ${scanRange ? scanRange : 'Auto (Lokaal)'}`);
        
        // local-devices voert de ARP scan uit. Als scanRange null is, scant het lokaal.
        const devices = await find(scanRange);

        console.log(`[SCAN] Klaar. ${devices.length} apparaten gevonden.`);
        
        res.json({
            success: true,
            devices: devices
        });

    } catch (error) {
        console.error('[SCAN] Fout bij netwerk scan:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Kon netwerk niet scannen. Controleer of de container met --network host draait en of de benodigde tools (net-tools) aanwezig zijn.' 
        });
    }
});

// --- API: PING ---
// Route om een specifiek IP-adres te pingen. Gebruikt een JSON body.
app.post('/api/ping', async (req, res) => {
    const { ip } = req.body;

    if (!ip) {
        return res.status(400).json({ success: false, message: 'Geen IP-adres opgegeven' });
    }

    try {
        console.log(`[PING] Pingen naar ${ip}...`);
        
        // Voer de ping uit (met een korte timeout en slechts 1 pakket)
        const resPing = await ping.promise.probe(ip, {
            timeout: 2,
            extra: ["-c", "1"] // Stuur slechts 1 pakket (Linux/macOS)
        });

        res.json({
            success: true,
            alive: resPing.alive, // true of false
            time: resPing.time, // Latency in ms
            output: resPing.output // Volledige ping output (voor debug)
        });

    } catch (error) {
        console.error('[PING] Fout:', error);
        res.status(500).json({ success: false, message: 'Ping mislukt. Controleer IP en netwerk.' });
    }
});

app.listen(PORT, () => {
    console.log(`Backend server draait op http://localhost:${PORT}`);
});
