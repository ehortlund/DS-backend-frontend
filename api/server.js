const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const User = require('./models/User');

const app = express();

// Middleware för att tolka JSON i förfrågningar
app.use(express.json());
app.use(cors());

// Anslut till MongoDB med felhantering
const connectToMongoDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            serverSelectionTimeoutMS: 5000 // Timeout efter 5 sekunder
        });
        console.log('Ansluten till MongoDB');
    } catch (error) {
        console.error('Fel vid anslutning till MongoDB:', error.message);
        // Vi returnerar inte ett fel här, utan låter serverless function fortsätta
        // och hantera felet i varje route
    }
};

// Kör anslutningen asynkront
connectToMongoDB();

// Middleware för att verifiera JWT-token
const verifyToken = (req, res, next) => {
    console.log('Kör verifyToken middleware...');
    const token = req.headers['authorization']?.split(' ')[1]; // Förväntar sig "Bearer <token>"
    console.log('Token:', token);

    if (!token) {
        console.log('Ingen token hittades, omdirigerar till login.html');
        return res.redirect('/login.html');
    }

    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        console.log('Token verifierad, decoded:', decoded);
        req.user = decoded; // Lägg till användarinformation i request-objektet
        next();
    } catch (error) {
        console.log('Token ogiltig, omdirigerar till login.html. Fel:', error.message);
        return res.redirect('/login.html');
    }
};

// Endpoint för att registrera en ny användare
app.post('/api/users/register', async (req, res) => {
    try {
        // Kontrollera om MongoDB är anslutet
        if (mongoose.connection.readyState !== 1) {
            throw new Error('MongoDB is not connected');
        }

        const { email, password } = req.body;

        // Kontrollera att e-post och lösenord finns
        if (!email || !password) {
            return res.status(400).json({ error: 'E-post och lösenord krävs' });
        }

        // Kontrollera om användaren redan finns
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'E-postadressen används redan' });
        }

        // Hasha lösenordet
        const hashedPassword = await bcrypt.hash(password, 10);

        // Skapa ny användare
        const user = new User({
            email,
            password: hashedPassword
        });

        // Spara användaren i databasen
        await user.save();

        res.status(201).json({ message: 'Användare skapad', user: { email: user.email } });
    } catch (error) {
        console.error('Fel vid registrering:', error.message);
        res.status(500).json({ error: `Registrering misslyckades: ${error.message}` });
    }
});

// Endpoint för att logga in
app.post('/api/users/login', async (req, res) => {
    try {
        // Kontrollera om MongoDB är anslutet
        if (mongoose.connection.readyState !== 1) {
            throw new Error('MongoDB is not connected');
        }

        const { email, password } = req.body;

        // Kontrollera att e-post och lösenord finns
        if (!email || !password) {
            return res.status(400).json({ error: 'E-post och lösenord krävs' });
        }

        // Hitta användaren
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Fel e-post eller lösenord' });
        }

        // Kontrollera lösenordet
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Fel e-post eller lösenord' });
        }

        // Generera JWT-token
        const token = jwt.sign({ userId: user._id, email: user.email }, 'mysecretkey', { expiresIn: '1h' });

        // Uppdatera lastLogin
        user.lastLogin = new Date();
        await user.save();

        res.json({ message: 'Inloggning lyckades', token });
    } catch (error) {
        console.error('Fel vid inloggning:', error.message);
        res.status(500).json({ error: `Inloggning misslyckades: ${error.message}` });
    }
});

// Endpoint för att hämta användarens information
app.get('/api/users/me', async (req, res) => {
    try {
        // Kontrollera om MongoDB är anslutet
        if (mongoose.connection.readyState !== 1) {
            throw new Error('MongoDB is not connected');
        }

        const user = await User.findOne({ email: 'test@example.com' });
        if (!user) {
            return res.status(404).json({ error: 'Användare hittades inte' });
        }
        res.json({ email: user.email, hasPaid: user.hasPaid });
    } catch (error) {
        console.error('Fel vid hämtning av användare:', error.message);
        res.status(500).json({ error: `Hämtning av användare misslyckades: ${error.message}` });
    }
});

// Skyddad route för deals.html
app.get('/deals.html', verifyToken, async (req, res) => {
    try {
        // Kontrollera om MongoDB är anslutet
        if (mongoose.connection.readyState !== 1) {
            throw new Error('MongoDB is not connected');
        }

        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.redirect('/login.html');
        }

        // Kontrollera om användaren har betalat
        if (!user.hasPaid) {
            return res.redirect('/payment.html'); // Vi skapar payment.html i ett senare steg
        }

        // Om allt är okej, serva deals.html
        res.sendFile(path.join(__dirname, '..', 'Dealscope VS', 'deals.html'));
    } catch (error) {
        console.error('Fel vid åtkomst av deals-sidan:', error.message);
        res.status(500).json({ error: `Fel vid åtkomst av deals-sidan: ${error.message}` });
    }
});

// Exportera appen som en serverless function för Vercel
module.exports = app;