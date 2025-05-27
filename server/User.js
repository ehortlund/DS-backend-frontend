const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
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
    }
});

module.exports = mongoose.model('User', userSchema);