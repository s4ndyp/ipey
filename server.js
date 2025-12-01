const express = require('express');
const cors = require('cors');
const find = require('local-devices');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors()); // Sta verzoeken van de HTML pagina toe
app.use(express.json());

// API Endpoint om te scannen
app.get('/api/scan', async (req, res) => {
    try {
        console.log('Start netwerk scan...');
        
        // Dit voert een ARP scan uit op het lokale netwerk
        // Let op: Dit scant het netwerk waar deze computer mee verbonden is.
        // Het negeert voor nu even de specifieke subnet input van de frontend 
        // omdat ARP gebonden is aan je fysieke interface.
        const devices = await find();

        console.log(`${devices.length} apparaten gevonden.`);
        
        // Stuur resultaat terug naar de frontend
        res.json({
            success: true,
            devices: devices
        });

    } catch (error) {
        console.error('Scan fout:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Kon netwerk niet scannen. Zorg dat je dit als Administrator/Root draait als dat nodig is.' 
        });
    }
});

app.listen(PORT, () => {
    console.log(`Backend server draait op http://localhost:${PORT}`);
    console.log(`Klaar om verzoeken van de IP Manager te ontvangen.`);
});
