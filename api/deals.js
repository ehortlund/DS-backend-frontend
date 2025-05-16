const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs').promises;
const { ensureMongoConnected } = require('./utils/db');
const User = require('./models/User');

console.log('Startar api/deals.js...');

module.exports = async (req, res) => {
    console.log('Anrop till api/deals.js mottaget...');
    console.log('Metod:', req.method);
    console.log('Headers:', req.headers);

    if (req.method !== 'GET') {
        console.log('Fel metod, returnerar 405...');
        return res.status(405).json({ error: 'Method not allowed' });
    }

    console.log('Kör verifyToken middleware...');
    // Hämta token från cookie
    const cookies = req.headers.cookie ? req.headers.cookie.split(';').reduce((acc, cookie) => {
        const [name, value] = cookie.trim().split('=');
        acc[name] = value;
        return acc;
    }, {}) : {};
    const token = cookies.token;
    console.log('Token från cookie:', token);

    if (!token) {
        console.log('Ingen token hittades, omdirigerar till login.html');
        res.setHeader('Set-Cookie', 'token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict');
        res.setHeader('Location', '/login.html');
        return res.status(307).end();
    }

    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        console.log('Token verifierad, decoded:', decoded);

        await ensureMongoConnected(req, res, async () => {
            const user = await User.findById(decoded.userId);
            if (!user) {
                console.log('Användare hittades inte, omdirigerar till login.html');
                res.setHeader('Set-Cookie', 'token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict');
                res.setHeader('Location', '/login.html');
                return res.status(307).end();
            }

            // Om allt är okej, läs in deals.html och skicka som svar
            try {
                const filePath = path.join(__dirname, '..', 'Dealscope VS', 'deals.html');
                console.log('Läser in deals.html från:', filePath);
                const fileContent = await fs.readFile(filePath, 'utf-8');
                console.log('deals.html laddad, skickar som svar...');
                res.setHeader('Content-Type', 'text/html');
                res.status(200).send(fileContent);
            } catch (fileError) {
                console.error('Fel vid läsning av deals.html:', fileError.message);
                res.status(500).json({ error: 'Kunde inte ladda deals.html: ' + fileError.message });
            }
        });
    } catch (error) {
        console.log('Token ogiltig, omdirigerar till login.html. Fel:', error.message);
        res.setHeader('Set-Cookie', 'token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict');
        res.setHeader('Location', '/login.html');
        return res.status(307).end();
    }
};