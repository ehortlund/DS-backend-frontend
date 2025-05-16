const mongoose = require('mongoose');
const User = require('./User');

exports.handler = async (event) => {
    if (event.httpMethod !== 'GET') {
        return {
            statusCode: 405,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    try {
        await mongoose.connect(process.env.MONGODB_URI);

        const user = await User.findOne({ email: 'test@example.com' });
        if (!user) {
            return {
                statusCode: 404,
                body: JSON.stringify({ error: 'Användare hittades inte' })
            };
        }

        return {
            statusCode: 200,
            body: JSON.stringify({ email: user.email, hasPaid: user.hasPaid })
        };
    } catch (error) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: `Hämtning av användare misslyckades: ${error.message}` })
        };
    } finally {
        await mongoose.connection.close();
    }
};