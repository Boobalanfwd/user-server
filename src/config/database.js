import mongoose from 'mongoose';
import { initializeIndexes } from '../models/user.js';

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_system', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    mongoose.connection.on('error', (err) => {
      console.error('MongoDB connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      console.log('MongoDB disconnected');
    });

    console.log(`MongoDB Connected: ${conn.connection.host}`);
    
    await initializeIndexes();

  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
};

export default connectDB; 