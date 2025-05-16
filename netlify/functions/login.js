const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const User = require('./User');

exports.handler = async (event) => {
    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    const { email, password } = JSON.parse(event.body);

    if (!email || !password) {
        return {
            statusCode: 400,
            body: JSON.stringify({ error: 'E-post och lösenord krävs' })
        };
    }

    try {
        await mongoose.connect(process.env.MONGODB_URI);

        const user = await User.findOne({ email });
        if (!user) {
            return {
                statusCode: 401,
                body: JSON.stringify({ error: 'Fel e-post eller lösenord' })
            };
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return {
                statusCode: 401,
                body: JSON.stringify({ error: 'Fel e-post eller lösenord' })
            };
        }

        const token = jwt.sign({ userId: user._id, email: user.email }, 'mysecretkey', { expiresIn: '1h' });

        user.lastLogin = new Date();
        await user.save();

        return {
            statusCode: 200,
            headers: {
                'Set-Cookie': `token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600`
            },
            body: JSON.stringify({ message: 'Inloggning lyckades' })
        };
    } catch (error) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: `Inloggning misslyckades: ${error.message}` })
        };
    } finally {
        await mongoose.connection.close();
    }
};