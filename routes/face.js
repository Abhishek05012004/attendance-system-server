const express = require("express")
const jwt = require("jsonwebtoken")
const User = require("../models/User")
const router = express.Router()

const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1]
    if (!token) return res.status(403).json({ error: "No token provided" })
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    const user = await User.findById(decoded.id)
    if (!user || !user.isActive) return res.status(403).json({ error: "Invalid token" })
    req.user = user
    next()
  } catch {
    return res.status(403).json({ error: "Invalid token" })
  }
}

const euclidean = (a = [], b = []) => {
  if (!a?.length || !b?.length || a.length !== b.length) return Number.POSITIVE_INFINITY
  let s = 0
  for (let i = 0; i < a.length; i++) {
    const d = a[i] - b[i]
    s += d * d
  }
  return Math.sqrt(s)
}

// Enroll face embedding
router.post("/enroll", auth, async (req, res) => {
  try {
    const { embedding, modelVersion = "face-api-0.22.2" } = req.body
    if (!Array.isArray(embedding) || embedding.length < 64) {
      return res.status(400).json({ error: "Invalid embedding" })
    }
    req.user.faceEmbedding = embedding.map(Number)
    req.user.faceEnrolled = true
    req.user.faceModelVersion = modelVersion
    await req.user.save()
    const safe = req.user.toObject()
    delete safe.password
    res.json({ message: "Face enrolled successfully", user: safe })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// Verify face embedding
router.post("/verify", auth, async (req, res) => {
  try {
    const { embedding } = req.body
    if (!req.user.faceEnrolled || !req.user.faceEmbedding?.length) {
      return res.status(412).json({ error: "Face not enrolled" })
    }
    if (!Array.isArray(embedding)) return res.status(400).json({ error: "Embedding is required" })
    const distance = euclidean(embedding, req.user.faceEmbedding)
    const threshold = 0.6
    res.json({ verified: distance <= threshold, distance, threshold })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

module.exports = router
