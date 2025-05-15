const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { ensureMongoConnected } = require('../utils/db');
const User = require('../models/User');

module.exports = async (req, res) => {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        await ensureMongoConnected(req, res, async () => {
            const { email, password } = req.body;

            // Kontrollera att e-post och lösenord finns
            if (!email || !password) {
                return res.status(400).json({ error: 'E-post och lösenord krävs' });
            }

            // Hitta användaren
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(401).json({ error: 'Fel e-post eller lösenord' });
            }

            // Kontrollera lösenordet
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ error: 'Fel e-post eller lösenord' });
            }

            // Generera JWT-token
            const token = jwt.sign({ userId: user._id, email: user.email }, 'mysecretkey', { expiresIn: '1h' });

            // Uppdatera lastLogin
            user.lastLogin = new Date();
            await user.save();

            res.json({ message: 'Inloggning lyckades', token });
        });
    } catch (error) {
        console.error('Fel vid inloggning:', error.message);
        res.status(500).json({ error: `Inloggning misslyckades: ${error.message}` });
    }
};