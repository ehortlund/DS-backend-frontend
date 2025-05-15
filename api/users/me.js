const { ensureMongoConnected } = require('../utils/db');
const User = require('../models/User');

module.exports = async (req, res) => {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        await ensureMongoConnected(req, res, async () => {
            const user = await User.findOne({ email: 'test@example.com' });
            if (!user) {
                return res.status(404).json({ error: 'Användare hittades inte' });
            }
            res.json({ email: user.email, hasPaid: user.hasPaid });
        });
    } catch (error) {
        console.error('Fel vid hämtning av användare:', error.message);
        res.status(500).json({ error: `Hämtning av användare misslyckades: ${error.message}` });
    }
};