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

// Helper to convert ArrayBuffer to base64url
function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ""
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
}

// Step 1: Get registration options
router.post("/register-options", auth, async (req, res) => {
  try {
    const user = req.user

    // Generate a challenge
    const challenge = crypto.randomBytes(32)
    const challengeBase64Url = arrayBufferToBase64Url(challenge)

    // Store challenge temporarily (5 minutes expiry)
    user.fingerprintChallenge = challengeBase64Url
    user.fingerprintChallengeExpiry = Date.now() + 300000
    await user.save()

    res.json({
      challenge: challengeBase64Url,
      rp: {
        name: "Employee Attendance System",
        id: "localhost",
      },
      user: {
        id: arrayBufferToBase64Url(Buffer.from(user._id.toString())),
        name: user.email,
        displayName: user.name,
      },
      pubKeyCredParams: [
        { alg: -7, type: "public-key" },
        { alg: -257, type: "public-key" },
      ],
      timeout: 60000,
      attestation: "direct",
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "preferred",
        residentKey: "preferred",
      },
    })
  } catch (error) {
    console.error("Error generating registration options:", error)
    res.status(500).json({ error: error.message })
  }
})

// Step 2: Register fingerprint credential
router.post("/register", auth, async (req, res) => {
  try {
    const user = req.user
    const { credentialId, attestationObject, clientDataJSON, transports, challenge } = req.body

    // Validate required fields
    if (!credentialId || credentialId.trim() === "") {
      return res.status(400).json({ error: "Credential ID is required" })
    }

    if (!challenge) {
      return res.status(400).json({ error: "Challenge is required" })
    }

    // Verify challenge
    if (!user.fingerprintChallenge) {
      return res.status(400).json({ error: "No challenge found. Please start enrollment again." })
    }

    if (user.fingerprintChallenge !== challenge) {
      return res.status(400).json({ error: "Invalid challenge" })
    }

    if (Date.now() > user.fingerprintChallengeExpiry) {
      user.fingerprintChallenge = undefined
      user.fingerprintChallengeExpiry = undefined
      await user.save()
      return res.status(400).json({ error: "Challenge expired. Please start enrollment again." })
    }

    // Check if credential already exists globally
    const existingCredentialGlobal = await User.findOne({
      "fingerprintCredentials.credentialId": credentialId,
    })

    if (existingCredentialGlobal) {
      return res.status(400).json({ error: "This fingerprint is already registered to another user" })
    }

    // Check if credential already exists for this user
    const existingCredential = user.fingerprintCredentials.find((c) => c.credentialId === credentialId)
    if (existingCredential) {
      return res.status(400).json({ error: "This fingerprint is already registered" })
    }

    user.fingerprintCredentials.push({
      credentialId: credentialId,
      attestationObject: attestationObject || "",
      clientDataJSON: clientDataJSON || "",
      counter: 0,
      transports: transports || [],
      createdAt: new Date(),
    })

    user.fingerprintEnrolled = true
    user.fingerprintChallenge = undefined
    user.fingerprintChallengeExpiry = undefined
    await user.save()

    res.json({
      message: "Fingerprint registered successfully",
      success: true,
    })
  } catch (error) {
    console.error("Error registering fingerprint:", error)
    res.status(500).json({ error: error.message })
  }
})

// Step 3: Get authentication options for fingerprint login
router.post("/auth-options", async (req, res) => {
  try {
    const { email } = req.body

    if (!email) {
      return res.status(400).json({ error: "Email is required" })
    }

    const user = await User.findOne({
      email: { $regex: new RegExp(`^${email}$`, "i") },
      isActive: true,
      fingerprintEnrolled: true,
    })

    if (!user) {
      return res.status(404).json({ error: "User not found or fingerprint not enrolled" })
    }

    // Generate challenge
    const challenge = crypto.randomBytes(32)
    const challengeBase64Url = arrayBufferToBase64Url(challenge)

    // Store challenge temporarily
    user.fingerprintAuthChallenge = challengeBase64Url
    user.fingerprintAuthChallengeExpiry = Date.now() + 300000
    await user.save()

    // Return allowed credentials
    const allowCredentials = user.fingerprintCredentials.map((cred) => ({
      id: cred.credentialId,
      type: "public-key",
      transports: cred.transports || [],
    }))

    res.json({
      challenge: challengeBase64Url,
      allowCredentials,
      timeout: 60000,
      userVerification: "preferred",
    })
  } catch (error) {
    console.error("Error generating auth options:", error)
    res.status(500).json({ error: error.message })
  }
})

// Step 4: Authenticate with fingerprint
router.post("/authenticate", async (req, res) => {
  try {
    const { email, credentialId, clientDataJSON, authenticatorData, signature, challenge } = req.body

    if (!email || !credentialId || !signature) {
      return res.status(400).json({ error: "Missing required fields" })
    }

    const user = await User.findOne({
      email: { $regex: new RegExp(`^${email}$`, "i") },
      isActive: true,
      fingerprintEnrolled: true,
    })

    if (!user) {
      return res.status(401).json({ error: "User not found or fingerprint not enrolled" })
    }

    // Verify challenge
    if (!user.fingerprintAuthChallenge || user.fingerprintAuthChallenge !== challenge) {
      return res.status(400).json({ error: "Invalid or expired challenge" })
    }

    if (Date.now() > user.fingerprintAuthChallengeExpiry) {
      user.fingerprintAuthChallenge = undefined
      user.fingerprintAuthChallengeExpiry = undefined
      await user.save()
      return res.status(400).json({ error: "Challenge expired" })
    }

    // Find the credential
    const credential = user.fingerprintCredentials.find((c) => c.credentialId === credentialId)
    if (!credential) {
      return res.status(401).json({ error: "Credential not found" })
    }

    // Clear challenge
    user.fingerprintAuthChallenge = undefined
    user.fingerprintAuthChallengeExpiry = undefined
    await user.save()

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
    console.error("Fingerprint authentication error:", error)
    res.status(500).json({ error: error.message })
  }
})

// Get enrolled fingerprints
router.get("/list", auth, async (req, res) => {
  try {
    const user = req.user

    const credentials = user.fingerprintCredentials.map((cred) => ({
      id: cred.credentialId,
      createdAt: cred.createdAt,
    }))

    res.json({
      fingerprintEnrolled: user.fingerprintEnrolled,
      credentials,
    })
  } catch (error) {
    console.error("Error fetching fingerprints:", error)
    res.status(500).json({ error: error.message })
  }
})

// Remove a fingerprint credential
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
    console.error("Error removing fingerprint:", error)
    res.status(500).json({ error: error.message })
  }
})

module.exports = router
