const express = require("express")
const Leave = require("../models/Leave")
const User = require("../models/User")
const Notification = require("../models/Notification") // Import Notification model
const jwt = require("jsonwebtoken")
const router = express.Router()

const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1]
    if (!token) return res.status(403).json({ error: "No token provided" })

    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.user = await User.findById(decoded.id)
    if (!req.user) return res.status(403).json({ error: "Invalid token" })

    next()
  } catch (error) {
    res.status(403).json({ error: "Invalid token" })
  }
}

const adminAuth = (req, res, next) => {
  if (req.user.role !== "admin" && req.user.role !== "manager" && req.user.role !== "hr") {
    return res.status(403).json({ error: "Admin, Manager, or HR access required" })
  }
  next()
}

// Submit leave request
router.post("/request", auth, async (req, res) => {
  try {
    const { leaveType, startDate, endDate, reason } = req.body

    // Calculate number of days
    const start = new Date(startDate)
    const end = new Date(endDate)
    const timeDiff = end.getTime() - start.getTime()
    const days = Math.ceil(timeDiff / (1000 * 3600 * 24)) + 1

    const leave = new Leave({
      user: req.user._id,
      leaveType,
      startDate: start,
      endDate: end,
      days,
      reason,
      status: "pending",
    })

    await leave.save()
    await leave.populate("user", "name employeeId department")

    // Create notification for admin, manager, and HR
    const notification = new Notification({
      type: "leave_request",
      message: `New leave request from ${req.user.name} (${req.user.employeeId}) for ${days} days (${leaveType}).`,
      link: "/leaves",
      recipientRoles: ["admin", "manager", "hr"],
      relatedId: leave._id,
      relatedModel: "Leave",
    })
    await notification.save()
    console.log("✅ Notification created for new leave request")

    res.json({
      message: "Leave request submitted successfully",
      leave,
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// Get leave requests (for employees - their own, for admin/manager - all)
router.get("/requests", auth, async (req, res) => {
  try {
    const { page: pageStr = "1", limit: limitStr = "10", status, userId } = req.query
    const page = Number.parseInt(pageStr)
    const limit = Number.parseInt(limitStr)

    const query = {}

    // If employee, only show their requests
    if (req.user.role === "employee") {
      query.user = req.user._id
    } else {
      // Admin/Manager can see all or filter by user
      if (userId) {
        query.user = userId
      }
    }

    if (status) {
      query.status = status
    }

    const leaves = await Leave.find(query)
      .populate("user", "name employeeId department position")
      .populate("approvedBy", "name")
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip((page - 1) * limit)

    const total = await Leave.countDocuments(query)

    res.json({
      leaves,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total,
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// Approve/Reject leave request (Admin/Manager only)
router.put("/requests/:id", auth, adminAuth, async (req, res) => {
  try {
    const { status, comments } = req.body // status: 'approved' or 'rejected'

    const leave = await Leave.findById(req.params.id)
    if (!leave) {
      return res.status(404).json({ error: "Leave request not found" })
    }

    leave.status = status
    leave.approvedBy = req.user._id
    leave.approvedAt = new Date()
    if (comments) {
      leave.comments = comments
    }

    await leave.save()
    await leave.populate("user", "name employeeId")
    await leave.populate("approvedBy", "name")

    res.json({
      message: `Leave request ${status} successfully`,
      leave,
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// Get leave statistics
router.get("/stats", auth, async (req, res) => {
  try {
    const query = req.user.role === "employee" ? { user: req.user._id } : {}

    const stats = await Leave.aggregate([
      { $match: query },
      {
        $group: {
          _id: "$status",
          count: { $sum: 1 },
          totalDays: { $sum: "$days" },
        },
      },
    ])

    const result = {
      pending: 0,
      approved: 0,
      rejected: 0,
      totalDays: 0,
    }

    stats.forEach((stat) => {
      result[stat._id] = stat.count
      if (stat._id === "approved") {
        result.totalDays = stat.totalDays
      }
    })

    res.json(result)
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

module.exports = router
