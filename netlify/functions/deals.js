const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs').promises;
const mongoose = require('mongoose');
const User = require('./User');

exports.handler = async (event) => {
    if (event.httpMethod !== 'GET') {
        return {
            statusCode: 405,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    const cookies = event.headers.cookie ? event.headers.cookie.split(';').reduce((acc, cookie) => {
        const [name, value] = cookie.trim().split('=');
        acc[name] = value;
        return acc;
    }, {}) : {};
    const token = cookies.token;

    if (!token) {
        return {
            statusCode: 307,
            headers: {
                'Set-Cookie': 'token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict',
                'Location': '/login.html'
            },
            body: ''
        };
    }

    try {
        const decoded = jwt.verify(token, 'mysecretkey');

        await mongoose.connect(process.env.MONGODB_URI);

        const user = await User.findById(decoded.userId);
        if (!user) {
            return {
                statusCode: 307,
                headers: {
                    'Set-Cookie': 'token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict',
                    'Location': '/login.html'
                },
                body: ''
            };
        }

        const filePath = path.join(__dirname, '..', '..', 'Dealscope VS', 'deals.html');
        const fileContent = await fs.readFile(filePath, 'utf-8');
        return {
            statusCode: 200,
            headers: {
                'Content-Type': 'text/html'
            },
            body: fileContent
        };
    } catch (error) {
        return {
            statusCode: 307,
            headers: {
                'Set-Cookie': 'token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict',
                'Location': '/login.html'
            },
            body: ''
        };
    } finally {
        await mongoose.connection.close();
    }
};