const mongoose = require('mongoose');
const User = require('../User');

module.exports = async (req, res) => {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        await mongoose.connect(process.env.MONGODB_URI);

        const user = await User.findOne({ email: 'test@example.com' });
        if (!user) {
            return res.status(404).json({ error: 'Användare hittades inte' });
        }

        res.status(200).json({ email: user.email, hasPaid: user.hasPaid });
    } catch (error) {
        res.status(500).json({ error: `Hämtning av användare misslyckades: ${error.message}` });
    } finally {
        await mongoose.connection.close();
    }
};