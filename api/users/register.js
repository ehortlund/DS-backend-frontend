const bcrypt = require('bcrypt');
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

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'E-postadressen används redan' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            email,
            password: hashedPassword
        });

        await user.save();

        res.status(201).json({ message: 'Användare skapad', user: { email: user.email } });
    } catch (error) {
        res.status(500).json({ error: `Registrering misslyckades: ${error.message}` });
    } finally {
        await mongoose.connection.close();
    }
};