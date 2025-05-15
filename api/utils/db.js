const mongoose = require('mongoose');

// Global variabel för att hålla reda på MongoDB-anslutningsstatus
let isMongoConnected = false;

// Anslut till MongoDB med felhantering och reconnection
const connectToMongoDB = async () => {
    if (isMongoConnected) return; // Om redan ansluten, hoppa över

    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            serverSelectionTimeoutMS: 5000, // Timeout efter 5 sekunder
            maxPoolSize: 10, // Max antal anslutningar
            minPoolSize: 1, // Min antal anslutningar
            heartbeatFrequencyMS: 10000, // Hålla anslutningen vid liv
        });
        isMongoConnected = true;
        console.log('Ansluten till MongoDB');
    } catch (error) {
        isMongoConnected = false;
        console.error('Fel vid anslutning till MongoDB:', error.message);
        // Försök återansluta efter 5 sekunder
        setTimeout(connectToMongoDB, 5000);
    }
};

// Middleware för att säkerställa MongoDB-anslutning
const ensureMongoConnected = async (req, res, next) => {
    if (!isMongoConnected) {
        await connectToMongoDB();
    }
    if (!isMongoConnected) {
        return res.status(500).json({ error: 'MongoDB is not connected' });
    }
    next();
};

module.exports = { connectToMongoDB, ensureMongoConnected };