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

// Helper function to verify signature
function verifySignature(publicKeyPem, signature, data) {
  try {
    const crypto = require("crypto")
    const verifier = crypto.createVerify("SHA256")
    verifier.update(data)
    return verifier.verify(publicKeyPem, signature)
  } catch (error) {
    console.error("Signature verification error:", error)
    return false
  }
}

// Step 1: Get registration options for fingerprint enrollment
router.post("/fingerprint/register-options", auth, async (req, res) => {
  try {
    const user = req.user
    const { deviceName } = req.body

    // Generate a challenge
    const challenge = crypto.randomBytes(32).toString("base64")

    // Store challenge temporarily (in production, use Redis or session)
    user.fingerprintChallenge = challenge
    user.fingerprintChallengeExpiry = Date.now() + 300000 // 5 minutes
    await user.save()

    res.json({
      challenge,
      userId: user._id.toString(),
      userName: user.email,
      userDisplayName: user.name,
      deviceName: deviceName || "My Device",
    })
  } catch (error) {
    console.error("Error generating registration options:", error)
    res.status(500).json({ error: error.message })
  }
})

// Step 2: Register fingerprint credential
router.post("/fingerprint/register", auth, async (req, res) => {
  try {
    const user = req.user
    const { credentialId, publicKey, counter, transports, deviceName, challenge } = req.body

    // Verify challenge
    if (!user.fingerprintChallenge || user.fingerprintChallenge !== challenge) {
      return res.status(400).json({ error: "Invalid or expired challenge" })
    }

    if (Date.now() > user.fingerprintChallengeExpiry) {
      return res.status(400).json({ error: "Challenge expired" })
    }

    // Check if credential already exists
    const existingCredential = user.fingerprintCredentials.find((c) => c.credentialId === credentialId)
    if (existingCredential) {
      return res.status(400).json({ error: "This fingerprint is already registered" })
    }

    // Add new credential
    user.fingerprintCredentials.push({
      credentialId,
      publicKey,
      counter: counter || 0,
      transports: transports || [],
      deviceName: deviceName || "Device",
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
router.post("/fingerprint/auth-options", async (req, res) => {
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
    const challenge = crypto.randomBytes(32).toString("base64")

    // Store challenge temporarily
    user.fingerprintAuthChallenge = challenge
    user.fingerprintAuthChallengeExpiry = Date.now() + 300000 // 5 minutes
    await user.save()

    // Return allowed credentials
    const allowCredentials = user.fingerprintCredentials.map((cred) => ({
      id: cred.credentialId,
      type: "public-key",
      transports: cred.transports,
    }))

    res.json({
      challenge,
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
router.post("/fingerprint/authenticate", async (req, res) => {
  try {
    const { email, credentialId, signature, clientData, counter, challenge } = req.body

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
      return res.status(400).json({ error: "Challenge expired" })
    }

    // Find the credential
    const credential = user.fingerprintCredentials.find((c) => c.credentialId === credentialId)
    if (!credential) {
      return res.status(401).json({ error: "Credential not found" })
    }

    // Verify signature
    const signatureBuffer = Buffer.from(signature, "base64")
    const clientDataBuffer = Buffer.from(clientData, "base64")

    const isValid = verifySignature(credential.publicKey, signatureBuffer, clientDataBuffer)

    if (!isValid) {
      return res.status(401).json({ error: "Signature verification failed" })
    }

    // Update counter for security
    if (counter > credential.counter) {
      credential.counter = counter
      await user.save()
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
router.get("/fingerprint/list", auth, async (req, res) => {
  try {
    const user = req.user

    const credentials = user.fingerprintCredentials.map((cred) => ({
      id: cred.credentialId,
      deviceName: cred.deviceName,
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
router.delete("/fingerprint/:credentialId", auth, async (req, res) => {
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
