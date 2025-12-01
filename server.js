const express = require('express');
const cors = require('cors');
const find = require('local-devices');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors()); // Sta verzoeken van andere domeinen/poorten toe
app.use(express.json());

// API Endpoint om te scannen
app.get('/api/scan', async (req, res) => {
    try {
        // 1. Lees de subnet parameter uit de URL (bijv. ?subnet=192.168.1.1-255)
        // Als deze leeg is, wordt 'scanRange' null.
        const scanRange = req.query.subnet || null;
        
        console.log(`Start netwerk scan... Range: ${scanRange ? scanRange : 'Auto (Lokaal)'}`);
        
        // 2. Voer de scan uit
        // Als scanRange null is, scant 'local-devices' automatisch het lokale subnet.
        // Als er wel een range is (bv '192.168.0.1-192.168.0.25'), wordt die gebruikt.
        const devices = await find(scanRange);

        console.log(`${devices.length} apparaten gevonden.`);
        
        // 3. Stuur resultaat terug naar de frontend
        res.json({
            success: true,
            devices: devices
        });

    } catch (error) {
        console.error('Scan fout:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Kon netwerk niet scannen. Controleer of het subnet formaat correct is (bv. 192.168.1.1-255) en of je voldoende rechten hebt.' 
        });
    }
});

app.listen(PORT, () => {
    console.log(`Backend server draait op http://localhost:${PORT}`);
});
