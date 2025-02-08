import mongoose from "mongoose";
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

export const connectDB = async () => {
    await mongoose.connect(process.env.MONGO_URL).then(() => console.log("DB Connected Successfully"));
}