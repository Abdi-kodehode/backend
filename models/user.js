import mongoose from "mongoose";
const { Schema } = mongoose;

const userSchema = new Schema({
  username: {
    type: String,
    trim: true,
    required: true,
  },
  email: {
    type: String,
    trim: true,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
    min: 6,
    max: 64,
  },
  // idempotencykey: String,
  stripe_customer_id: {
    type: String,
    subscriptions: [],
  }
});

export default mongoose.model("User", userSchema);
