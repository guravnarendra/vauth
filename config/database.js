const mongoose = require('mongoose');
require('dotenv').config();

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);

    // Create indexes for better performance
    await createIndexes();
  } catch (error) {
    console.error('Database connection error:', error);
    process.exit(1);
  }
};

const createIndexes = async () => {
  try {
    const User = require('../models/User');
    const Token = require('../models/Token');
    const Session = require('../models/Session');

    // Create indexes with error handling for existing indexes
    try {
      await User.createIndexes();
      console.log('User indexes created/verified successfully');
    } catch (error) {
      if (error.code === 86) { // IndexKeySpecsConflict
        console.log('User indexes already exist, skipping...');
      } else {
        throw error;
      }
    }

    try {
      await Token.createIndexes();
      console.log('Token indexes created/verified successfully');
    } catch (error) {
      if (error.code === 86) {
        console.log('Token indexes already exist, skipping...');
      } else {
        throw error;
      }
    }

    try {
      await Session.createIndexes();
      console.log('Session indexes created/verified successfully');
    } catch (error) {
      if (error.code === 86) {
        console.log('Session indexes already exist, skipping...');
      } else {
        throw error;
      }
    }

    console.log('Database indexes setup completed');
  } catch (error) {
    console.error('Error creating indexes:', error);
    // Don't exit process for index errors, just log them
  }
};

module.exports = connectDB;