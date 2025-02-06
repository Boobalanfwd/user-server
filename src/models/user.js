import mongoose from "mongoose";

if (mongoose.models.User) {
  delete mongoose.models.User;
}

const userSchema = new mongoose.Schema(
  {
    identifier: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

userSchema.set("autoIndex", false);
userSchema.index({ identifier: 1 }, { unique: true });

userSchema.pre("save", function (next) {
  next();
});

export const User = mongoose.model("User", userSchema);

export const initializeIndexes = async () => {
  try {
    await User.collection.dropIndexes();
    await User.collection.createIndex({ identifier: 1 }, { unique: true });
  } catch (error) {
    console.error("Error resetting indexes:", error);
  }
};
