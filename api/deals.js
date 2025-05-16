const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs').promises;
const mongoose = require('mongoose');
const User = require('/models/User');

module.exports = async (req, res) => {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const cookies = req.headers.cookie ? req.headers.cookie.split(';').reduce((acc, cookie) => {
        const [name, value] = cookie.trim().split('=');
        acc[name] = value;
        return acc;
    }, {}) : {};
    const token = cookies.token;

    if (!token) {
        res.setHeader('Set-Cookie', 'token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict');
        res.setHeader('Location', '/login.html');
        return res.status(307).end();
    }

    try {
        const decoded = jwt.verify(token, 'mysecretkey');

        await mongoose.connect(process.env.MONGODB_URI);

        const user = await User.findById(decoded.userId);
        if (!user) {
            res.setHeader('Set-Cookie', 'token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict');
            res.setHeader('Location', '/login.html');
            return res.status(307).end();
        }

        const filePath = path.join(__dirname, '..', 'Dealscope VS', 'deals.html');
        const fileContent = await fs.readFile(filePath, 'utf-8');
        res.setHeader('Content-Type', 'text/html');
        res.status(200).send(fileContent);
    } catch (error) {
        res.setHeader('Set-Cookie', 'token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict');
        res.setHeader('Location', '/login.html');
        return res.status(307).end();
    } finally {
        await mongoose.connection.close();
    }
};