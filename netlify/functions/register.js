const bcrypt = require('bcrypt');
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

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return {
                statusCode: 400,
                body: JSON.stringify({ error: 'E-postadressen används redan' })
            };
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            email,
            password: hashedPassword
        });

        await user.save();

        return {
            statusCode: 201,
            body: JSON.stringify({ message: 'Användare skapad', user: { email: user.email } })
        };
    } catch (error) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: `Registrering misslyckades: ${error.message}` })
        };
    } finally {
        await mongoose.connection.close();
    }
};