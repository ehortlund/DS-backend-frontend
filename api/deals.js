const jwt = require('jsonwebtoken');
const path = require('path');
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
        return res.redirect('/login.html');
    }

    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        console.log('Token verifierad, decoded:', decoded);

        await ensureMongoConnected(req, res, async () => {
            const user = await User.findById(decoded.userId);
            if (!user) {
                return res.redirect('/login.html');
            }

            // Kontrollera om användaren har betalat (kommentera ut för att testa deals.html)
            // if (!user.hasPaid) {
            //     return res.redirect('/payment.html');
            // }

            // Om allt är okej, serva deals.html
            res.sendFile(path.join(__dirname, '..', 'Dealscope VS', 'deals.html'));
        });
    } catch (error) {
        console.log('Token ogiltig, omdirigerar till login.html. Fel:', error.message);
        return res.redirect('/login.html');
    }
};