const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs').promises; // Använd fs.promises för asynkron filhantering
const { ensureMongoConnected } = require('./utils/db');
const User = require('./models/User');

module.exports = async (req, res) => {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    console.log('Kör verifyToken middleware...');
    const token = req.headers['authorization']?.split(' ')[1]; // Förväntar sig "Bearer <token>"
    console.log('Token:', token);

    if (!token) {
        console.log('Ingen token hittades, omdirigerar till login.html');
        return res.status(307).set('Location', '/login.html').end();
    }

    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        console.log('Token verifierad, decoded:', decoded);

        await ensureMongoConnected(req, res, async () => {
            const user = await User.findById(decoded.userId);
            if (!user) {
                console.log('Användare hittades inte, omdirigerar till login.html');
                return res.status(307).set('Location', '/login.html').end();
            }

            // Om allt är okej, läs in deals.html och skicka som svar
            try {
                const filePath = path.join(__dirname, '..', 'Dealscope VS', 'deals.html');
                const fileContent = await fs.readFile(filePath, 'utf-8');
                res.status(200).set('Content-Type', 'text/html').send(fileContent);
            } catch (fileError) {
                console.error('Fel vid läsning av deals.html:', fileError.message);
                res.status(500).json({ error: 'Kunde inte ladda deals.html: ' + fileError.message });
            }
        });
    } catch (error) {
        console.log('Token ogiltig, omdirigerar till login.html. Fel:', error.message);
        return res.status(307).set('Location', '/login.html').end();
    }
};