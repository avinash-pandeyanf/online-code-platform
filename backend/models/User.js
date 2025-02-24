const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: String, // In production, hash this with bcrypt
});

module.exports = mongoose.model('User', userSchema);