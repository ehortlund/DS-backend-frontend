const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const User = require('/models/User');

module.exports = async (req, res) => {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'E-post och lösenord krävs' });
    }

    try {
        await mongoose.connect(process.env.MONGODB_URI);

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Fel e-post eller lösenord' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Fel e-post eller lösenord' });
        }

        const token = jwt.sign({ userId: user._id, email: user.email }, 'mysecretkey', { expiresIn: '1h' });

        user.lastLogin = new Date();
        await user.save();

        res.setHeader('Set-Cookie', `token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600`);
        return res.status(200).json({ message: 'Inloggning lyckades' });
    } catch (error) {
        res.status(500).json({ error: `Inloggning misslyckades: ${error.message}` });
    } finally {
        await mongoose.connection.close();
    }
};