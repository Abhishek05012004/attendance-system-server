const mongoose = require("mongoose")

const attendanceSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    date: {
      type: String,
      required: true,
    },
    checkIn: {
      type: String,
      default: null,
    },
    checkOut: {
      type: String,
      default: null,
    },
    workingHours: {
      type: Number,
      default: 0,
    },
    location: {
      checkIn: { type: String, default: null },
      checkOut: { type: String, default: null },
    },
    notes: String,
    status: {
      type: String,
      enum: ["present", "absent", "late", "half_day"],
      default: "present",
    },
    face: {
      checkIn: { type: [Number], default: undefined },
      checkOut: { type: [Number], default: undefined },
      version: { type: String, default: "face-api-0.22.2" },
    },
    checkInFaceEmbedding: { type: [Number], default: undefined },
    checkOutFaceEmbedding: { type: [Number], default: undefined },
  },
  {
    timestamps: true,
  },
)

// FIXED: Pre-save middleware to calculate working hours
attendanceSchema.pre("save", function (next) {
  if (this.checkIn && this.checkOut) {
    try {
      console.log(`Calculating working hours for ${this.date}: ${this.checkIn} to ${this.checkOut}`)

      // Helper function to parse time string to seconds
      const parseTime = (timeStr) => {
        const parts = timeStr.split(":")
        const hours = Number.parseInt(parts[0], 10)
        const minutes = Number.parseInt(parts[1], 10)
        const seconds = parts[2] ? Number.parseInt(parts[2], 10) : 0
        return hours * 3600 + minutes * 60 + seconds
      }

      const checkInSeconds = parseTime(this.checkIn)
      const checkOutSeconds = parseTime(this.checkOut)

      let diffSeconds
      if (checkOutSeconds >= checkInSeconds) {
        // Same day checkout
        diffSeconds = checkOutSeconds - checkInSeconds
      } else {
        // Next day checkout (e.g., night shift)
        diffSeconds = 24 * 3600 - checkInSeconds + checkOutSeconds
      }

      // Convert to hours and round to 2 decimal places
      this.workingHours = Math.round((diffSeconds / 3600) * 100) / 100

      console.log(`Working hours calculated: ${this.workingHours}`)
    } catch (error) {
      console.error("Error calculating working hours:", error)
      this.workingHours = 0
    }
  } else {
    this.workingHours = 0
  }
  next()
})

// Index for better query performance
attendanceSchema.index({ user: 1, date: 1 }, { unique: true })
attendanceSchema.index({ date: 1 })
attendanceSchema.index({ user: 1 })

module.exports = mongoose.model("Attendance", attendanceSchema)
