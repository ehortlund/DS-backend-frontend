const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser');
const User = require('./User');
console.log('STRIPE_SECRET_KEY:', process.env.STRIPE_SECRET_KEY);
if (!process.env.STRIPE_SECRET_KEY) {
    throw new Error('STRIPE_SECRET_KEY is not set in environment variables');
}
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '..', 'Dealscope VS')));

app.post('/api/users/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'E-post och lösenord krävs' });
    }

    try {
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
    }
});

app.post('/api/users/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'E-post och lösenord krävs' });
    }

    try {
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

        res.cookie('token', token, { httpOnly: true, sameSite: 'strict', maxAge: 3600000 });
        res.status(200).json({ message: 'Inloggning lyckades' });
    } catch (error) {
        res.status(500).json({ error: `Inloggning misslyckades: ${error.message}` });
    }
});

app.get('/api/users/me', async (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ error: 'Ingen token, omdirigerar till login' });
    }

    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(404).json({ error: 'Användare hittades inte' });
        }

        res.status(200).json({ email: user.email, hasPaid: user.hasPaid });
    } catch (error) {
        res.status(401).json({ error: 'Ogiltig token, omdirigerar till login' });
    }
});

app.get('/deals.html', async (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        res.clearCookie('token');
        return res.redirect('/login.html');
    }

    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        const user = await User.findById(decoded.userId);
        if (!user) {
            res.clearCookie('token');
            return res.redirect('/login.html');
        }

        if (!user.hasPaid) {
            return res.redirect('/payment.html');
        }

        res.sendFile(path.join(__dirname, '..', 'Dealscope VS', 'deals.html'));
    } catch (error) {
        res.clearCookie('token');
        return res.redirect('/login.html');
    }
});

app.post('/api/users/logout', (req, res) => {
    res.clearCookie('token');
    res.status(200).json({ message: 'Utloggning lyckades' });
});

app.post('/api/create-checkout-session', async (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ error: 'Ingen token, omdirigerar till login' });
    }

    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(404).json({ error: 'Användare hittades inte' });
        }

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: 'usd',
                        product_data: {
                            name: 'Dealscope Subscription',
                        },
                        unit_amount: 1000, // $10.00 i cent
                    },
                    quantity: 1,
                },
            ],
            mode: 'payment',
            success_url: `https://dealscope.io/deals.html`,
            cancel_url: `https://dealscope.io/payment.html`,
            metadata: {
                userId: user._id.toString()
            }
        });

        res.json({ id: session.id });
    } catch (error) {
        res.status(500).json({ error: `Kunde inte skapa betalning: ${error.message}` });
    }
});

app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    console.log('Received Stripe webhook request');
    console.log('Webhook Secret:', webhookSecret);
    console.log('Signature:', sig);
    console.log('Request Body:', req.body);

    if (!webhookSecret) {
        console.error('Webhook Secret is not set');
        return res.status(400).send('Webhook Secret is not set');
    }

    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
        console.log('Webhook event constructed:', event.type);
    } catch (err) {
        console.error('Webhook Error:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        console.log('Checkout session completed event received');
        const session = event.data.object;
        const userId = session.metadata.userId;
        console.log('Session metadata:', session.metadata);

        if (!userId) {
            console.error('No userId found in session metadata');
            return res.status(400).send('No userId found in session metadata');
        }

        try {
            const user = await User.findById(userId);
            if (user) {
                console.log('User found:', user.email);
                user.hasPaid = true;
                await user.save();
                console.log('Updated user hasPaid to true for user:', user.email);
            } else {
                console.error('User not found for userId:', userId);
            }
        } catch (error) {
            console.error('Error updating user hasPaid:', error);
        }
    } else {
        console.log('Unhandled event type:', event.type);
    }

    res.json({ received: true });
});

const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Connected to MongoDB');
        app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    })
    .catch(err => console.error('MongoDB connection error:', err));