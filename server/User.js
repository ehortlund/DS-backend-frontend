const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true, // Lägger till trim för att ta bort onödiga mellanslag
        lowercase: true // Gör e-post till gemener för konsistens
    },
    password: {
        type: String,
        required: true
    },
    hasPaid: {
        type: Boolean,
        default: false
    },
    lastLogin: {
        type: Date,
        default: Date.now
    },
    username: {
        type: String,
        required: true,
        unique: true, // Säkerställer att användarnamn är unikt
        trim: true, // Tar bort onödiga mellanslag
        minlength: 3, // Minsta längd för användarnamn
        maxlength: 15 // Maxlängd för användarnamn
    },
    stripeCustomerId: {
        type: String,
        default: null 
    },
    defaultPaymentMethodId: {
        type: String,
        default: null // Spårar den valda betalningsmetoden från Stripe
    }
});

module.exports = mongoose.model('User', userSchema);