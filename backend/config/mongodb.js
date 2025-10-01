import mongoose from "mongoose";

const connectDB = async () =>{
    
    if(!process.env.MONGODB_URI){
        throw new Error("MONGODB_URI is not defined in enviroment variables");
    }

    try {
        await mongoose.connect(`${process.env.MONGODB_URI}/MernAuth`);
        console.log("Database Connected");
    } catch (error) {
        console.error("Database connection failed:", error);
        process.exit(1);
    }
};

export default connectDB;