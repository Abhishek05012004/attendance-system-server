const mongoose = require("mongoose")

const biometricCredentialSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    credentialId: {
      type: Buffer,
      required: true,
      unique: true,
    },
    publicKey: {
      type: Buffer,
      required: true,
    },
    counter: {
      type: Number,
      default: 0,
    },
    transports: [String],
    deviceName: {
      type: String,
      default: "My Fingerprint",
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    lastUsed: Date,
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true },
)

module.exports = mongoose.model("BiometricCredential", biometricCredentialSchema)
