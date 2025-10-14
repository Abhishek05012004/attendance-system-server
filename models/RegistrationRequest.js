const mongoose = require("mongoose")

const registrationRequestSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    department: { type: String, required: true },
    position: { type: String, required: true },
    phone: { type: String, required: true },
    address: { type: String, required: true },
    role: { type: String, enum: ["admin", "employee", "manager", "hr"], default: "employee" },
    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },
    adminCode: { type: String, required: true },
    submittedAt: { type: Date, default: Date.now },
    reviewedAt: Date,
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    rejectionReason: String,
    faceEmbedding: { type: [Number], default: undefined },
    faceModelVersion: { type: String, default: "face-api-0.22.2" },
  },
  {
    timestamps: true,
  },
)

module.exports = mongoose.model("RegistrationRequest", registrationRequestSchema)
