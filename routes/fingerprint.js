const express = require("express")
const router = express.Router()
const User = require("../models/User")
const jwt = require("jsonwebtoken")
const crypto = require("crypto")

// Auth middleware
const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1]
    if (!token) return res.status(403).json({ error: "No token provided" })

    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.user = await User.findById(decoded.id)
    if (!req.user || !req.user.isActive) return res.status(403).json({ error: "Invalid token or inactive user" })

    next()
  } catch (error) {
    res.status(403).json({ error: "Invalid token" })
  }
}

router.post("/enroll", auth, async (req, res) => {
  try {
    const user = req.user
    const { fingerprintData, deviceName } = req.body

    if (!fingerprintData || typeof fingerprintData !== "string") {
      return res.status(400).json({ error: "Fingerprint data is required" })
    }

    // Generate a unique credential ID for this fingerprint
    const credentialId = crypto.randomBytes(16).toString("hex")

    // Store fingerprint for this user
    user.fingerprintCredentials.push({
      credentialId: credentialId,
      attestationObject: fingerprintData, // Store the fingerprint template
      clientDataJSON: deviceName || "Unknown Device",
      counter: 0,
      transports: [],
      createdAt: new Date(),
    })

    user.fingerprintEnrolled = true
    await user.save()

    console.log("[v0] Fingerprint enrolled for user:", user._id, "Device:", deviceName)

    res.json({
      message: "Fingerprint enrolled successfully",
      success: true,
      credentialId: credentialId,
    })
  } catch (error) {
    console.error("[v0] Error enrolling fingerprint:", error)
    res.status(500).json({ error: error.message })
  }
})

router.get("/check-enrollment", auth, async (req, res) => {
  try {
    const user = req.user

    res.json({
      fingerprintEnrolled: user.fingerprintEnrolled,
      credentialsCount: user.fingerprintCredentials.length,
    })
  } catch (error) {
    console.error("[v0] Error checking enrollment:", error)
    res.status(500).json({ error: error.message })
  }
})

router.get("/list", auth, async (req, res) => {
  try {
    const user = req.user

    const credentials = user.fingerprintCredentials.map((cred) => ({
      id: cred.credentialId,
      deviceName: cred.clientDataJSON,
      createdAt: cred.createdAt,
    }))

    res.json({
      fingerprintEnrolled: user.fingerprintEnrolled,
      credentials,
    })
  } catch (error) {
    console.error("[v0] Error fetching fingerprints:", error)
    res.status(500).json({ error: error.message })
  }
})

router.delete("/:credentialId", auth, async (req, res) => {
  try {
    const user = req.user
    const { credentialId } = req.params

    user.fingerprintCredentials = user.fingerprintCredentials.filter((c) => c.credentialId !== credentialId)

    if (user.fingerprintCredentials.length === 0) {
      user.fingerprintEnrolled = false
    }

    await user.save()

    res.json({
      message: "Fingerprint removed successfully",
      success: true,
    })
  } catch (error) {
    console.error("[v0] Error removing fingerprint:", error)
    res.status(500).json({ error: error.message })
  }
})

router.post("/authenticate", async (req, res) => {
  try {
    const { email, fingerprintData } = req.body

    if (!email || !fingerprintData) {
      return res.status(400).json({ error: "Email and fingerprint data are required" })
    }

    const user = await User.findOne({
      email: { $regex: new RegExp(`^${email}$`, "i") },
      isActive: true,
      fingerprintEnrolled: true,
    })

    if (!user) {
      return res.status(401).json({ error: "User not found or fingerprint not enrolled" })
    }

    // Simple fingerprint matching (in production, use proper biometric matching)
    const hasMatchingFingerprint = user.fingerprintCredentials.some(
      (cred) => cred.attestationObject === fingerprintData,
    )

    if (!hasMatchingFingerprint) {
      return res.status(401).json({ error: "Fingerprint does not match" })
    }

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" })

    res.json({
      message: "Fingerprint authentication successful",
      token,
      user: {
        id: user._id,
        employeeId: user.employeeId,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        position: user.position,
        fingerprintEnrolled: user.fingerprintEnrolled,
      },
    })
  } catch (error) {
    console.error("[v0] Fingerprint authentication error:", error)
    res.status(500).json({ error: error.message })
  }
})

module.exports = router
