const mongoose = require("mongoose")

const userSchema = new mongoose.Schema(
  {
    employeeId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["admin", "employee", "manager", "hr"], default: "employee" },
    department: { type: String, required: true },
    position: { type: String, required: true },
    phone: String,
    address: String,
    dateOfJoining: { type: Date, default: Date.now },
    salary: Number,
    isActive: { type: Boolean, default: true },
    profileImage: String,
    workingHours: { type: Number, default: 8 }, // hours per day
    // Password reset fields
    resetPasswordToken: String,
    resetPasswordExpiry: Date,
    faceEmbedding: { type: [Number], default: undefined }, // 128-d descriptor
    faceEnrolled: { type: Boolean, default: false },
    faceModelVersion: { type: String, default: "face-api-0.22.2" },
  },
  {
    timestamps: true,
  },
)

module.exports = mongoose.model("User", userSchema)
