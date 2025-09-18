const express = require("express")
const User = require("../models/User")
const Attendance = require("../models/Attendance")
const Leave = require("../models/Leave")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")
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
  if (req.user.role !== "admin" && req.user.role !== "hr") {
    return res.status(403).json({ error: "Admin or HR access required" })
  }
  next()
}

const managerAuth = (req, res, next) => {
  if (req.user.role !== "admin" && req.user.role !== "manager" && req.user.role !== "hr") {
    return res.status(403).json({ error: "Admin, Manager, or HR access required" })
  }
  next()
}

// Helper function to get current date
const getCurrentDate = () => {
  const now = new Date()
  const year = now.getFullYear()
  const month = String(now.getMonth() + 1).padStart(2, "0")
  const day = String(now.getDate()).padStart(2, "0")
  return `${year}-${month}-${day}`
}

// FIXED: Allow manager/HR to access users list for reports
router.get("/", auth, managerAuth, async (req, res) => {
  try {
    const { page: pageStr = "1", limit: limitStr = "10", search, department } = req.query
    const page = Number.parseInt(pageStr)
    const limit = Number.parseInt(limitStr)

    const query = { isActive: true }

    if (search) {
      query.$or = [
        { name: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } },
        { employeeId: { $regex: search, $options: "i" } },
      ]
    }

    if (department) {
      query.department = department
    }

    const users = await User.find(query)
      .select("-password")
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip((page - 1) * limit)

    const total = await User.countDocuments(query)

    res.json({
      users,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total,
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

router.get("/departments", auth, async (req, res) => {
  try {
    const departments = await User.distinct("department", { isActive: true })
    res.json(departments)
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

router.put("/:id", auth, adminAuth, async (req, res) => {
  try {
    const { name, email, department, position, phone, address, salary, role } = req.body

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { name, email, department, position, phone, address, salary, role },
      { new: true, runValidators: true },
    ).select("-password")

    if (!user) {
      return res.status(404).json({ error: "User not found" })
    }

    res.json({ message: "User updated successfully", user })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

router.delete("/:id", auth, adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { isActive: false }, { new: true })

    if (!user) {
      return res.status(404).json({ error: "User not found" })
    }

    res.json({ message: "User deactivated successfully" })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// FIXED: Dashboard stats with correct date handling and department overview
router.get("/dashboard-stats", auth, managerAuth, async (req, res) => {
  try {
    const today = getCurrentDate()
    console.log("Dashboard stats - Today's date:", today)

    // Count ALL active users
    const totalEmployees = await User.countDocuments({ isActive: true })

    // Count present today (users who have checked in TODAY only)
    const presentToday = await Attendance.countDocuments({
      date: today,
      checkIn: { $exists: true, $ne: null, $ne: "" },
    })

    console.log("Present today count:", presentToday)

    // Calculate absent today correctly
    const absentToday = Math.max(0, totalEmployees - presentToday)

    // Get department-wise stats for ALL users (restored original functionality)
    const departmentStats = await User.aggregate([
      { $match: { isActive: true } },
      { $group: { _id: "$department", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ])

    // Calculate attendance rate correctly
    const attendanceRate = totalEmployees > 0 ? Math.min(100, Math.round((presentToday / totalEmployees) * 100)) : 0

    res.json({
      totalEmployees,
      presentToday,
      absentToday,
      attendanceRate,
      departmentStats,
    })
  } catch (error) {
    console.error("Dashboard stats error:", error)
    res.status(500).json({ error: error.message })
  }
})

// Get recent attendance for admin dashboard (today's data only)
router.get("/recent-attendance", auth, managerAuth, async (req, res) => {
  try {
    const today = getCurrentDate()

    const recentAttendance = await Attendance.find({ date: today })
      .populate("user", "name employeeId department position")
      .sort({ createdAt: -1 })
      .limit(10)

    res.json(recentAttendance)
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// Mark attendance for employees (Admin/Manager can mark for others)
router.post("/mark-attendance", auth, adminAuth, async (req, res) => {
  try {
    const { userId, action, location } = req.body
    const today = getCurrentDate()

    const targetUser = await User.findById(userId)
    if (!targetUser) {
      return res.status(404).json({ error: "User not found" })
    }

    if (action === "checkin") {
      const exists = await Attendance.findOne({ user: userId, date: today })
      if (exists && exists.checkIn) {
        return res.status(400).json({ message: "Already checked in today" })
      }

      const checkInTime = new Date().toLocaleTimeString("en-US", { hour12: false })

      if (exists) {
        exists.checkIn = checkInTime
        if (location) exists.location.checkIn = location
        await exists.save()
        await exists.populate("user", "name employeeId")

        res.json({
          message: `Checked in ${targetUser.name} successfully`,
          attendance: exists,
        })
      } else {
        const attendance = new Attendance({
          user: userId,
          date: today,
          checkIn: checkInTime,
          location: { checkIn: location },
        })

        await attendance.save()
        await attendance.populate("user", "name employeeId")

        res.json({
          message: `Checked in ${targetUser.name} successfully`,
          attendance,
        })
      }
    } else if (action === "checkout") {
      const record = await Attendance.findOne({ user: userId, date: today })
      if (!record) {
        return res.status(404).json({ message: "No check-in record found for today" })
      }

      if (record.checkOut) {
        return res.status(400).json({ message: "Already checked out today" })
      }

      record.checkOut = new Date().toLocaleTimeString("en-US", { hour12: false })
      if (location) {
        record.location.checkOut = location
      }

      await record.save()
      await record.populate("user", "name employeeId")

      res.json({
        message: `Checked out ${targetUser.name} successfully`,
        attendance: record,
      })
    }
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

module.exports = router
