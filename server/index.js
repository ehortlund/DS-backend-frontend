const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser');
const User = require('./User');
require('dotenv').config(); // Lägg till dotenv för att läsa .env-filer

const app = express();

app.use(cookieParser());
app.use(express.json());
app.use(express.raw({ type: 'application/json' })); // För webhook
app.use(express.static(path.join(__dirname, '..', 'Dealscope VS')));

const stripe = process.env.STRIPE_SECRET_KEY
    ? require('stripe')(process.env.STRIPE_SECRET_KEY)
    : null;

if (!stripe) {
    console.error('Failed to initialize Stripe: STRIPE_SECRET_KEY is missing');
    process.exit(1); // Avsluta om Stripe inte kan initieras
}

app.post('/api/create-payment-intent', async (req, res) => {
    const token = req.cookies.token;
    const { amount, paymentMethodId } = req.body;

    console.log('Received /api/create-payment-intent request:', { tokenExists: !!token, amount, paymentMethodId });

    if (!token) {
        return res.status(401).json({ error: 'No token, redirecting to login' });
    }

    if (!amount || !paymentMethodId) {
        return res.status(400).json({ error: 'Amount and payment method ID are required' });
    }

    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        console.log('Creating payment intent with amount:', amount, 'and paymentMethodId:', paymentMethodId);
        const paymentIntent = await stripe.paymentIntents.create({
            amount: Math.round(amount), // Säkerställ heltal i cent
            currency: 'usd',
            payment_method: paymentMethodId,
            confirmation_method: 'automatic', // Ändra till automatic
            // Ta bort confirm: true eftersom automatic hanterar det
            return_url: process.env.RENDER_URL || 'https://your-render-url.com'
        });

        console.log('Payment intent created, client_secret:', paymentIntent.client_secret);
        if (!paymentIntent.client_secret) {
            throw new Error('No client secret returned from Stripe');
        }

        res.json({ clientSecret: paymentIntent.client_secret });
    } catch (error) {
        console.error('Payment Intent error details:', error);
        let statusCode = 500;
        let errorMessage = 'Error creating payment intent';
        if (error.type === 'StripeInvalidRequestError') {
            statusCode = 400;
            errorMessage = `Stripe error: ${error.message}`;
        } else if (error.code === 'ETIMEDOUT' || error.code === 'ECONNRESET') {
            statusCode = 502;
            errorMessage = 'Gateway error: Connection to Stripe failed';
        } else if (error.message.includes('STRIPE_SECRET_KEY')) {
            statusCode = 500;
            errorMessage = 'Stripe configuration error: Check your secret key';
        }
        res.status(statusCode).json({ error: errorMessage });
    }
});

app.post('/api/stripe-webhook', async (req, res) => {
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

    if (event.type === 'payment_intent.succeeded') {
        console.log('Payment intent succeeded event received');
        const paymentIntent = event.data.object;
        const userId = paymentIntent.metadata.userId;
        console.log('Payment Intent metadata:', paymentIntent.metadata);

        if (!userId) {
            console.error('No userId found in payment intent metadata');
            return res.status(400).send('No userId found in payment intent metadata');
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

app.post('/api/users/register', async (req, res) => {
    const { email, username, password } = req.body;

    if (!email || !username || !password) {
        return res.status(400).json({ error: 'E-post, användarnamn och lösenord krävs' });
    }

    try {
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            if (existingUser.email === email) {
                return res.status(400).json({ error: 'E-postadressen används redan' });
            }
            if (existingUser.username === username) {
                return res.status(400).json({ error: 'Användarnamnet är redan taget' });
            }
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            email,
            username,
            password: hashedPassword
        });

        await user.save();

        res.status(201).json({ message: 'Användare skapad', user: { email: user.email, username: user.username } });
    } catch (error) {
        res.status(500).json({ error: `Registrering misslyckades: ${error.message}` });
    }
});

app.post('/api/users/login', async (req, res) => {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
        return res.status(400).json({ error: 'E-post eller användarnamn och lösenord krävs' });
    }

    try {
        const user = await User.findOne({
            $or: [
                { email: identifier },
                { username: identifier }
            ]
        });

        if (!user) {
            return res.status(401).json({ error: 'Fel e-post, användarnamn eller lösenord' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Fel e-post, användarnamn eller lösenord' });
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

        res.status(200).json({ email: user.email, username: user.username, hasPaid: user.hasPaid });
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
            return res.redirect('/plans.html');
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

app.get('/api/users/payment-methods', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'No token, redirecting to login' });

    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        const user = await User.findById(decoded.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        if (!user.stripeCustomerId) {
            return res.status(404).json({ error: 'No payment methods associated with this account' });
        }

        const paymentMethods = await stripe.paymentMethods.list({
            customer: user.stripeCustomerId,
            type: 'card'
        });

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
    const token = req.cookies.token;
    const { paymentMethodId, makeDefault } = req.body;
    if (!token) return res.status(401).json({ error: 'No token, redirecting to login' });
    if (!paymentMethodId) return res.status(400).json({ error: 'Payment method ID is required' });

    try {
        const decoded = jwt.verify(token, 'mysecretkey');
        let user = await User.findById(decoded.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        if (!user.stripeCustomerId) {
            const customer = await stripe.customers.create({
                email: user.email,
                name: user.username
            });
            user.stripeCustomerId = customer.id;
            await user.save();
        }

        await stripe.paymentMethods.attach(paymentMethodId, { customer: user.stripeCustomerId });
        if (makeDefault) {
            await stripe.customers.update(user.stripeCustomerId, {
                invoice_settings: { default_payment_method: paymentMethodId }
            });
            user.defaultPaymentMethodId = paymentMethodId;
            await user.save();
        }

        res.status(200).json({ message: 'Payment method added/updated successfully' });
    } catch (error) {
        console.error('Error adding/updating payment method:', error);
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
        if (paymentMethods.data.length <= 1) {
            return res.status(400).json({ error: 'Cannot remove the only payment method. Add a new one first.' });
        }

        await stripe.paymentMethods.detach(paymentMethodId);
        if (user.defaultPaymentMethodId === paymentMethodId) {
            user.defaultPaymentMethodId = null;
            await user.save();
        }

        res.status(200).json({ message: 'Payment method removed successfully' });
    } catch (error) {
        console.error('Error removing payment method:', error);
        res.status(500).json({ error: `Error removing payment method: ${error.message}` });
    }
});

const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Connected to MongoDB');
        app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    })
    .catch(err => console.error('MongoDB connection error:', err));