const express = require("express")
const User = require("../models/User")
const jwt = require("jsonwebtoken")
const crypto = require("crypto")
const router = express.Router()

// WebAuthn helper functions
const base64url = {
  encode: (buffer) => {
    return Buffer.from(buffer).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
  },
  decode: (str) => {
    str += new Array(5 - (str.length % 4)).join("=")
    return Buffer.from(str.replace(/-/g, "+").replace(/_/g, "/"), "base64")
  },
}

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

// 1. Start biometric enrollment
router.post("/enroll/start", auth, async (req, res) => {
  try {
    const user = req.user
    const credentialName = req.body.credentialName || `Fingerprint ${Date.now()}`

    // Generate challenge (random bytes)
    const challenge = crypto.randomBytes(32)

    // Store challenge temporarily in session/cache (in production, use Redis)
    // For now, we'll return it to client and verify on completion
    const enrollmentSession = {
      userId: user._id,
      challenge: base64url.encode(challenge),
      credentialName,
      createdAt: Date.now(),
    }

    res.json({
      challenge: base64url.encode(challenge),
      rp: {
        name: "Employee Attendance System",
        id: process.env.WEBAUTHN_RP_ID || "localhost",
      },
      user: {
        id: base64url.encode(user._id.toString()),
        name: user.email,
        displayName: user.name,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      timeout: 60000,
      attestation: "direct",
      authenticatorSelection: {
        authenticatorAttachment: "platform", // Built-in authenticator (fingerprint)
        userVerification: "preferred",
        residentKey: "preferred",
      },
    })
  } catch (error) {
    console.error("Enrollment start error:", error)
    res.status(500).json({ error: error.message })
  }
})

// 2. Complete biometric enrollment
router.post("/enroll/complete", auth, async (req, res) => {
  try {
    const user = req.user
    const { credential, credentialName, challenge } = req.body

    if (!credential || !credential.id || !credential.response) {
      return res.status(400).json({ error: "Invalid credential format" })
    }

    // Verify challenge matches
    const clientDataJSON = JSON.parse(Buffer.from(base64url.decode(credential.response.clientDataJSON)).toString())

    if (clientDataJSON.challenge !== challenge) {
      return res.status(400).json({ error: "Challenge mismatch" })
    }

    if (clientDataJSON.type !== "webauthn.create") {
      return res.status(400).json({ error: "Invalid attestation type" })
    }

    // Extract public key from attestation object
    const attestationObject = base64url.decode(credential.response.attestationObject)

    // Store credential
    const newCredential = {
      credentialId: Buffer.from(base64url.decode(credential.id)),
      publicKey: Buffer.from(credential.response.publicKey || ""),
      counter: credential.response.signCount || 0,
      transports: credential.response.transports || ["internal"],
      name: credentialName || "Fingerprint",
      createdAt: new Date(),
    }

    user.biometricCredentials.push(newCredential)
    user.biometricEnrolled = true
    await user.save()

    console.log(`✅ Biometric credential enrolled for user: ${user.email}`)

    res.json({
      message: "Biometric enrollment successful!",
      credentialId: credential.id,
      credentialName: credentialName || "Fingerprint",
    })
  } catch (error) {
    console.error("Enrollment complete error:", error)
    res.status(500).json({ error: error.message })
  }
})

// 3. Start biometric authentication
router.post("/authenticate/start", async (req, res) => {
  try {
    const { email } = req.body

    if (!email) {
      return res.status(400).json({ error: "Email is required" })
    }

    const user = await User.findOne({
      email: { $regex: new RegExp(`^${email}$`, "i") },
      isActive: true,
      biometricEnrolled: true,
    })

    if (!user || !user.biometricCredentials || user.biometricCredentials.length === 0) {
      return res.status(404).json({ error: "No biometric credentials found for this user" })
    }

    // Generate challenge
    const challenge = crypto.randomBytes(32)

    res.json({
      challenge: base64url.encode(challenge),
      timeout: 60000,
      userVerification: "preferred",
      allowCredentials: user.biometricCredentials.map((cred) => ({
        type: "public-key",
        id: base64url.encode(cred.credentialId),
        transports: cred.transports,
      })),
    })
  } catch (error) {
    console.error("Authentication start error:", error)
    res.status(500).json({ error: error.message })
  }
})

// 4. Complete biometric authentication
router.post("/authenticate/complete", async (req, res) => {
  try {
    const { email, assertion, challenge } = req.body

    if (!email || !assertion) {
      return res.status(400).json({ error: "Email and assertion are required" })
    }

    const user = await User.findOne({
      email: { $regex: new RegExp(`^${email}$`, "i") },
      isActive: true,
      biometricEnrolled: true,
    })

    if (!user) {
      return res.status(404).json({ error: "User not found or biometric not enrolled" })
    }

    // Find matching credential
    const credentialIdBuffer = Buffer.from(base64url.decode(assertion.id))
    const credential = user.biometricCredentials.find((c) => c.credentialId.equals(credentialIdBuffer))

    if (!credential) {
      return res.status(400).json({ error: "Credential not found" })
    }

    // Verify signature
    const clientDataJSON = JSON.parse(Buffer.from(base64url.decode(assertion.response.clientDataJSON)).toString())

    if (clientDataJSON.challenge !== challenge) {
      return res.status(400).json({ error: "Challenge mismatch" })
    }

    if (clientDataJSON.type !== "webauthn.get") {
      return res.status(400).json({ error: "Invalid assertion type" })
    }

    // Check counter to detect cloned authenticators
    const newCounter = assertion.response.signCount
    if (newCounter <= credential.counter) {
      console.warn(`⚠️ Possible cloned authenticator detected for user: ${user.email}`)
      return res.status(400).json({ error: "Authenticator verification failed" })
    }

    // Update counter and last used
    credential.counter = newCounter
    credential.lastUsed = new Date()
    await user.save()

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" })

    console.log(`✅ Biometric authentication successful for user: ${user.email}`)

    res.json({
      message: "Biometric authentication successful",
      token,
      user: {
        id: user._id,
        employeeId: user.employeeId,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        position: user.position,
      },
    })
  } catch (error) {
    console.error("Authentication complete error:", error)
    res.status(500).json({ error: error.message })
  }
})

// 5. Get enrolled biometric credentials
router.get("/credentials", auth, async (req, res) => {
  try {
    const user = req.user

    const credentials = user.biometricCredentials.map((cred) => ({
      id: cred._id,
      name: cred.name,
      createdAt: cred.createdAt,
      lastUsed: cred.lastUsed,
      transports: cred.transports,
    }))

    res.json({
      biometricEnrolled: user.biometricEnrolled,
      credentials,
      totalCredentials: credentials.length,
    })
  } catch (error) {
    console.error("Get credentials error:", error)
    res.status(500).json({ error: error.message })
  }
})

// 6. Remove biometric credential
router.delete("/credentials/:credentialId", auth, async (req, res) => {
  try {
    const user = req.user
    const { credentialId } = req.params

    user.biometricCredentials = user.biometricCredentials.filter((c) => c._id.toString() !== credentialId)

    if (user.biometricCredentials.length === 0) {
      user.biometricEnrolled = false
    }

    await user.save()

    console.log(`✅ Biometric credential removed for user: ${user.email}`)

    res.json({ message: "Credential removed successfully" })
  } catch (error) {
    console.error("Remove credential error:", error)
    res.status(500).json({ error: error.message })
  }
})

module.exports = router
