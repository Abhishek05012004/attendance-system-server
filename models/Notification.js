const mongoose = require("mongoose")

const notificationSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: ["leave_request", "registration_request"],
      required: true,
    },
    message: {
      type: String,
      required: true,
    },
    link: {
      type: String, // Frontend route to navigate to
      required: true,
    },
    recipientRoles: [
      {
        // Roles that should see this notification
        type: String,
        enum: ["admin", "manager", "hr"],
        required: true,
      },
    ],
    readBy: [
      {
        // Array of user IDs who have read this notification
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    relatedId: {
      // ID of the actual leave/registration request
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      refPath: "relatedModel", // Dynamic reference
    },
    relatedModel: {
      // To store which model relatedId refers to
      type: String,
      required: true,
      enum: ["Leave", "RegistrationRequest"],
    },
  },
  {
    timestamps: true,
  },
)

notificationSchema.index({ recipientRoles: 1, createdAt: -1 })
notificationSchema.index({ relatedId: 1 })

module.exports = mongoose.model("Notification", notificationSchema)
