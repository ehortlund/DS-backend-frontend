const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors'); // Se till att detta finns
require('dotenv').config();

const User = require('./models/User');

const app = express();

// Middleware för att tolka JSON i förfrågningar
app.use(express.json());
app.use(cors()); // Se till att detta finns

// Logga för att kontrollera om dotenv laddas
console.log('Laddar dotenv...');
console.log('process.env:', process.env);
console.log('MONGODB_URI:', process.env.MONGODB_URI);

// Anslut till MongoDB
mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('Ansluten till MongoDB'))
.catch(err => {
    console.error('Fel vid anslutning till MongoDB:');
    console.error('Felmeddelande:', err.message);
    console.error('Felstack:', err.stack);
});

// Endpoint för att registrera en ny användare
app.post('/api/users/register', async (req, res) => {
    try {
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
        res.status(500).json({ error: 'Fel vid registrering: ' + error.message });
    }
});

// Endpoint för att logga in
app.post('/api/users/login', async (req, res) => {
    try {
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
        res.status(500).json({ error: 'Fel vid inloggning: ' + error.message });
    }
});

// Endpoint för att hämta användarens information
app.get('/api/users/me', async (req, res) => {
    try {
        // Detta är en temporär endpoint utan autentisering för att testa
        const user = await User.findOne({ email: 'test@example.com' });
        if (!user) {
            return res.status(404).json({ error: 'Användare hittades inte' });
        }
        res.json({ email: user.email, hasPaid: user.hasPaid });
    } catch (error) {
        res.status(500).json({ error: 'Fel vid hämtning av användare: ' + error.message });
    }
});

// Starta servern på port 3000
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Servern körs på port ${PORT}`);
});