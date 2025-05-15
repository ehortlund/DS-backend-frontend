const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { ensureMongoConnected } = require('../utils/db');
const User = require('../models/User');

module.exports = async (req, res) => {
    console.log('Kör /api/users/login...');
    console.log('Request body:', req.body);

    if (req.method !== 'POST') {
        console.log('Fel metod, returnerar 405...');
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        await ensureMongoConnected(req, res, async () => {
            console.log('MongoDB ansluten, fortsätter med inloggning...');
            const { email, password } = req.body;

            // Kontrollera att e-post och lösenord finns
            if (!email || !password) {
                console.log('E-post eller lösenord saknas, returnerar 400...');
                return res.status(400).json({ error: 'E-post och lösenord krävs' });
            }

            // Hitta användaren
            console.log('Söker användare med email:', email);
            const user = await User.findOne({ email });
            if (!user) {
                console.log('Användare hittades inte, returnerar 401...');
                return res.status(401).json({ error: 'Fel e-post eller lösenord' });
            }

            // Kontrollera lösenordet
            console.log('Jämför lösenord...');
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                console.log('Fel lösenord, returnerar 401...');
                return res.status(401).json({ error: 'Fel e-post eller lösenord' });
            }

            // Generera JWT-token
            console.log('Genererar JWT-token...');
            const token = jwt.sign({ userId: user._id, email: user.email }, 'mysecretkey', { expiresIn: '1h' });

            // Uppdatera lastLogin
            console.log('Uppdaterar lastLogin...');
            user.lastLogin = new Date();
            await user.save();

            console.log('Inloggning lyckades, omdirigerar till deals.html med token...');
            // Skicka token som en query-parameter och omdirigera till deals.html med 303 See Other
            res.setHeader('Location', `/deals.html?token=${token}`);
            return res.status(303).end(); // 303 tvingar en GET-förfrågan
        });
    } catch (error) {
        console.error('Fel vid inloggning:', error.message);
        res.status(500).json({ error: `Inloggning misslyckades: ${error.message}` });
    }
};