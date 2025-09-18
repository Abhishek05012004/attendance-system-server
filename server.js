// Make sure to install nodemailer: npm install nodemailer
const express = require("express")
const cors = require("cors")
const mongoose = require("mongoose")
require("dotenv").config()

const authRoutes = require("./routes/auth")
const attendanceRoutes = require("./routes/attendance")
const userRoutes = require("./routes/users")
const leaveRoutes = require("./routes/leave")

const app = express()

// Middleware
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:5173",
    credentials: true,
  }),
)
app.use(express.json({ limit: "10mb" }))
app.use(express.urlencoded({ extended: true, limit: "10mb" }))

// Database connection - only connect in production or if not on Vercel
if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  console.log("Connecting to MongoDB...")
  console.log("MongoDB URI:", process.env.MONGO_URI ? "Set" : "Not set")
  console.log("JWT Secret:", process.env.JWT_SECRET ? "Set" : "Not set")

  mongoose
    .connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then(() => {
      console.log("✅ MongoDB connected successfully")
      console.log("Database name:", mongoose.connection.name)
    })
    .catch((err) => {
      console.error("❌ MongoDB connection error:", err)
      process.exit(1)
    })
} else {
  console.log("Running on Vercel - MongoDB connection will be handled by serverless functions")
}

// Routes
app.use("/api/auth", authRoutes)
app.use("/api/attendance", attendanceRoutes)
app.use("/api/users", userRoutes)
app.use("/api/leave", leaveRoutes)

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? "Connected" : "Disconnected",
    environment: {
      nodeEnv: process.env.NODE_ENV || 'development',
      mongoUri: !!process.env.MONGO_URI,
      jwtSecret: !!process.env.JWT_SECRET,
      frontendUrl: process.env.FRONTEND_URL || "http://localhost:5173",
      vercel: !!process.env.VERCEL,
    },
  })
})

// Add this before the 404 handler
app.get("/api/auth/login", (req, res) => {
  res.json({
    message: "Login endpoint - use POST method with email and password",
    method: "POST",
    endpoint: "/api/auth/login",
    body: {
      email: "your-email@example.com",
      password: "your-password",
    },
  })
})

// 404 handler
app.use("*", (req, res) => {
  console.log("404 - Route not found:", req.originalUrl)
  res.status(404).json({ error: "Route not found" })
})

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Global error handler:", err.stack)
  res.status(500).json({ error: "Something went wrong!" })
})

// Only listen locally if not on Vercel
if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  const PORT = process.env.PORT || 5000
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`)
    console.log(`🌐 Health check: http://localhost:${PORT}/api/health`)
    console.log(`🔐 Auth endpoint: http://localhost:${PORT}/api/auth/login`)
  })
}

// Export the Express API for Vercel
module.exports = app