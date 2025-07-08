const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser');
const User = require('./User');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware-sektion
// Konfigurera CORS och cookie-parser
app.use(cors({
    origin: 'https://dealscope.io',
    credentials: true,
    exposedHeaders: ['Set-Cookie', 'Authorization'] // Tillåt dessa headers för cookie-hantering
}));
app.use(cookieParser());

// Rutt-sektion
// Statisk filservering
app.use(express.static(path.join(__dirname, '..', 'Dealscope VS')));

// Specifika rutter som kräver rå data (före JSON-parser)
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    console.log('Webhook endpoint hit at https://dealscope.io/api/stripe-webhook');
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    console.log('Webhook Secret:', webhookSecret ? 'Set' : 'Not set');
    console.log('Signature:', sig);
    console.log('Raw Request Body:', req.body.toString());

    if (!webhookSecret) {
        console.error('Webhook Secret is not set');
        return res.status(400).send('Webhook Secret is not set');
    }

    let event;
    try {
        const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
        console.log('Webhook event constructed:', event.type, 'with ID:', event.id);
    } catch (err) {
        console.error('Webhook Error:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        console.log('Checkout session completed event received, processing...');
        const session = event.data.object;
        const userId = session.metadata?.userId;
        console.log('Checkout session metadata:', session.metadata);

        if (!userId) {
            console.error('No userId found in checkout session metadata, session ID:', session.id);
            return res.status(400).send('No userId found in checkout session metadata');
        }

        try {
            const user = await User.findById(userId);
            if (user) {
                console.log('User found:', user.email, 'with ID:', userId);
                user.hasPaid = true;
                await user.save();
                console.log('Updated user hasPaid to true for user:', user.email, 'ID:', userId);
            } else {
                console.error('User not found for userId:', userId, 'in session:', session.id);
            }
        } catch (error) {
            console.error('Error updating user hasPaid:', error.message, 'for userId:', userId);
        }
    } else {
        console.log('Unhandled event type:', event.type, 'with ID:', event.id);
    }

    res.status(200).json({ received: true });
});

app.get('/plans.html', async (req, res) => {
    console.log('Serving /plans.html route');
    const token = req.cookies.token;
    if (!token) {
        console.log('No token found, redirecting to login.html');
        return res.redirect('/login.html');
    }

    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        const user = await User.findById(decoded.userId);
        if (!user) {
            res.clearCookie('token');
            console.log('User not found, redirecting to login.html');
            return res.redirect('/login.html');
        }

        const data = await readFile(path.join(__dirname, '..', 'Dealscope VS', 'plans.html'), 'utf8');
        const publishableKey = process.env.STRIPE_PUBLISHABLE_KEY;
        console.log('STRIPE_PUBLISHABLE_KEY from environment:', publishableKey);
        if (!publishableKey) {
            console.error('STRIPE_PUBLISHABLE_KEY is not set in environment');
            return res.status(500).send('Missing Stripe Publishable Key');
        }
        const updatedHtml = data.replace('{{STRIPE_PUBLISHABLE_KEY}}', publishableKey);
        console.log('Generated HTML meta tag:', updatedHtml.match(/<meta name="stripe-publishable-key" content="[^"]*"/));
        res.send(updatedHtml);
    } catch (error) {
        console.error('Error in plans.html route:', error.message);
        res.status(500).send('Server Error');
    }
});

app.get('/deals.html', async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        res.clearCookie('token');
        return res.redirect('https://dealscope.io/login.html');
    }
    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        const user = await User.findById(decoded.userId);
        if (!user) {
            res.clearCookie('token');
            return res.redirect('https://dealscope.io/login.html');
        }
        if (!user.hasPaid) return res.redirect('https://dealscope.io/plans.html');
        res.sendFile(path.join(__dirname, '..', 'Dealscope VS', 'deals.html'));
    } catch (error) {
        res.clearCookie('token');
        return res.redirect('https://dealscope.io/login.html');
    }
});

// Middleware för JSON-parsing och autentisering
app.use(express.json());

// Autentiseringsmiddleware
app.use(async (req, res, next) => {
    const token = req.cookies.token;
    console.log('Auth middleware - Checking token:', token ? 'Found' : 'Not set');
    if (!token) {
        console.log('No token, skipping authentication for this request');
        return next();
    }

    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        console.log('Decoded token successfully:', decoded);
        req.user = await User.findById(decoded.userId);
        console.log('Auth middleware - User:', req.user ? req.user._id : 'Not found');
        if (!req.user) throw new Error('User not found');
        if (!req.user.stripeCustomerId) {
            const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
            const customer = await stripe.customers.create({ email: req.user.email });
            req.user.stripeCustomerId = customer.id;
            await req.user.save();
            console.log('Created new Stripe customer:', customer.id);
        }
        next();
    } catch (error) {
        console.error('Auth middleware error details:', error.message, 'Stack:', error.stack);
        return res.status(401).json({ error: 'Invalid token, redirecting to login' });
    }
});

// API-endpoints
app.post('/api/users/register', async (req, res) => {
    const { email, username, password } = req.body;
    if (!email || !username || !password) {
        return res.status(400).json({ error: 'E-post, användarnamn och lösenord krävs' });
    }
    try {
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            if (existingUser.email === email) return res.status(400).json({ error: 'E-postadressen används redan' });
            if (existingUser.username === username) return res.status(400).json({ error: 'Användarnamnet är redan taget' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ email, username, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'Användare skapad', user: { email: user.email, username: user.username } });
    } catch (error) {
        res.status(500).json({ error: `Registrering misslyckades: ${error.message}` });
    }
});

app.post('/api/users/login', async (req, res) => {
    const { identifier, password } = req.body;
    if (!identifier || !password) return res.status(400).json({ error: 'E-post eller användarnamn och lösenord krävs' });
    try {
        const user = await User.findOne({ $or: [{ email: identifier }, { username: identifier }] });
        if (!user) return res.status(401).json({ error: 'Fel e-post, användarnamn eller lösenord' });
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ error: 'Fel e-post, användarnamn eller lösenord' });
        const token = jwt.sign({ userId: user._id, email: user.email }, 'mysecretkey', { expiresIn: '1h' });
        user.lastLogin = new Date();
        await user.save();
        res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 3600000 });
        console.log('Login successful, token set:', token);
        res.status(200).json({ message: 'Inloggning lyckades' });
    } catch (error) {
        console.error('Login error:', error.message, 'Stack:', error.stack);
        res.status(500).json({ error: `Inloggning misslyckades: ${error.message}` });
    }
});

app.get('/api/users/me', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Ingen token, omdirigerar till login' });
    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        console.log('Decoded token successfully:', decoded);
        const user = await User.findById(decoded.userId);
        if (!user) return res.status(404).json({ error: 'Användare hittades inte' });
        res.status(200).json({ email: user.email, username: user.username, hasPaid: user.hasPaid });
    } catch (error) {
        console.error('Token verification error:', error.message, 'Stack:', error.stack);
        res.status(401).json({ error: 'Invalid token, redirecting to login' });
    }
});

app.post('/api/users/logout', (req, res) => {
    res.clearCookie('token');
    res.status(200).json({ message: 'Utloggning lyckades' });
});

app.get('/api/users/payment-methods', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'No token, redirecting to login' });
    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        const user = await User.findById(decoded.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (!user.stripeCustomerId) return res.status(404).json({ error: 'No payment methods associated with this account' });
        const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
        const paymentMethods = await stripe.paymentMethods.list({ customer: user.stripeCustomerId, type: 'card' });
        const formattedMethods = paymentMethods.data.map(method => ({
            id: method.id,
            last4: method.card.last4,
            brand: method.card.brand,
            expMonth: method.card.exp_month,
            expYear: method.card.exp_year,
            isDefault: method.id === user.defaultPaymentMethodId
        }));
        res.status(200).json({ paymentMethods: formattedMethods });
    } catch (error) {
        console.error('Error fetching payment methods:', error);
        res.status(500).json({ error: `Error fetching payment methods: ${error.message}` });
    }
});

app.post('/api/users/payment-methods', async (req, res) => {
    try {
        const { paymentMethodId, makeDefault } = req.body;
        if (!req.user || !req.user.stripeCustomerId) {
            console.error('No user or stripeCustomerId in request:', req.user);
            return res.status(401).json({ error: 'User not authenticated or no Stripe customer ID' });
        }

        const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
        // Hämta befintlig kund från Stripe
        let customer;
        try {
            customer = await stripe.customers.retrieve(req.user.stripeCustomerId);
            console.log('Retrieved customer:', customer.id);
        } catch (retrieveError) {
            console.error('Error retrieving customer:', retrieveError);
            return res.status(500).json({ error: `Error retrieving customer: ${retrieveError.message}` });
        }

        // Ta bort den gamla betalningsmetoden om den finns och makeDefault är true
        if (makeDefault && customer.invoice_settings && customer.invoice_settings.default_payment_method) {
            console.log('Detaching old payment method:', customer.invoice_settings.default_payment_method);
            try {
                await stripe.paymentMethods.detach(customer.invoice_settings.default_payment_method);
                console.log('Old payment method detached successfully');
            } catch (detachError) {
                console.error('Error detaching old payment method:', detachError);
                return res.status(500).json({ error: `Error detaching old payment method: ${detachError.message}` });
            }
        }

        // Bifoga den nya betalningsmetoden till kunden (endast om den inte redan är bifogad)
        const existingMethods = await stripe.paymentMethods.list({ customer: req.user.stripeCustomerId, type: 'card' });
        if (!existingMethods.data.some(method => method.id === paymentMethodId)) {
            console.log('Attaching new payment method:', paymentMethodId);
            try {
                await stripe.paymentMethods.attach(paymentMethodId, { customer: req.user.stripeCustomerId });
                console.log('New payment method attached successfully');
            } catch (attachError) {
                console.error('Error attaching new payment method:', attachError);
                return res.status(500).json({ error: `Error attaching new payment method: ${attachError.message}` });
            }
        } else {
            console.log('PaymentMethod already attached:', paymentMethodId);
        }

        // Uppdatera standardbetalningsmetod
        console.log('Updating customer with new default payment method:', paymentMethodId);
        try {
            await stripe.customers.update(req.user.stripeCustomerId, {
                invoice_settings: { default_payment_method: paymentMethodId },
            });
            console.log('Customer updated with new default payment method');
        } catch (updateError) {
            console.error('Error updating customer:', updateError);
            return res.status(500).json({ error: `Error updating customer: ${updateError.message}` });
        }

        // Uppdatera användaren i databasen med defaultPaymentMethodId
        req.user.defaultPaymentMethodId = paymentMethodId;
        await req.user.save();
        console.log('User updated with new defaultPaymentMethodId:', paymentMethodId);

        res.json({ message: 'Payment method updated successfully' });
    } catch (error) {
        console.error('Error in payment-methods endpoint:', error);
        res.status(500).json({ error: `Error adding/updating payment method: ${error.message}` });
    }
});

app.delete('/api/users/payment-methods/:paymentMethodId', async (req, res) => {
    const token = req.cookies.token;
    const paymentMethodId = req.params.paymentMethodId;
    if (!token) return res.status(401).json({ error: 'No token, redirecting to login' });
    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        const user = await User.findById(decoded.userId);
        if (!user || !user.stripeCustomerId) return res.status(404).json({ error: 'User or payment customer not found' });
        const paymentMethods = await stripe.paymentMethods.list({ customer: user.stripeCustomerId, type: 'card' });
        if (paymentMethods.data.length <= 1) return res.status(400).json({ error: 'Cannot remove the only payment method. Add a new one first.' });
        await stripe.paymentMethods.detach(paymentMethodId);
        if (user.defaultPaymentMethodId === paymentMethodId) {
            user.defaultPaymentMethodId = paymentMethods.data.find(m => m.id !== paymentMethodId)?.id || null;
            await user.save();
        }
        res.status(200).json({ message: 'Payment method removed successfully' });
    } catch (error) {
        console.error('Error removing payment method:', error);
        res.status(400).json({ error: `Error removing payment method: ${error.message}` });
    }
});

const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Connected to MongoDB');
        app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    })
    .catch(err => console.error('MongoDB connection error:', err));