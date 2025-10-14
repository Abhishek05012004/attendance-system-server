const express = require("express")
const Attendance = require("../models/Attendance")
const User = require("../models/User")
const Leave = require("../models/Leave")
const jwt = require("jsonwebtoken")
const router = express.Router()

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

const adminAuth = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" })
  }
  next()
}

const managerAuth = (req, res, next) => {
  if (req.user.role !== "admin" && req.user.role !== "manager" && req.user.role !== "hr") {
    return res.status(403).json({ error: "Admin, Manager, or HR access required" })
  }
  next()
}

// Helper function to get current date in YYYY-MM-DD format
const getCurrentDate = (tzOffsetMinutes) => {
  const now = getLocalNow(tzOffsetMinutes)
  const year = now.getFullYear()
  const month = String(now.getMonth() + 1).padStart(2, "0")
  const day = String(now.getDate()).padStart(2, "0")
  return `${year}-${month}-${day}`
}

// Helper function to get current time in HH:MM:SS format
const getCurrentTime = (tzOffsetMinutes) => {
  const now = getLocalNow(tzOffsetMinutes)
  const hours = String(now.getHours()).padStart(2, "0")
  const minutes = String(now.getMinutes()).padStart(2, "0")
  const seconds = String(now.getSeconds()).padStart(2, "0")
  return `${hours}:${minutes}:${seconds}`
}

const getClientTzOffset = (req) => {
  const hdr = req.headers["x-tz-offset-minutes"]
  if (hdr === undefined) return null
  const n = Number(hdr)
  return Number.isFinite(n) ? n : null
}

// Given a timezone offset in minutes (as from Date#getTimezoneOffset),
// return a Date object representing "now" in the client's local time.
const getLocalNow = (tzOffsetMinutes) => {
  const nowUtc = new Date()
  if (typeof tzOffsetMinutes === "number" && !Number.isNaN(tzOffsetMinutes)) {
    // Convert server-now (UTC-based) to client's local time by subtracting the offset
    // Example: IST offset = -330 => now + 330 minutes
    return new Date(nowUtc.getTime() - tzOffsetMinutes * 60 * 1000)
  }
  // Fallback to server local time (keeps old behavior for legacy clients)
  return nowUtc
}

const getCurrentDateFromBase = (baseDate) => {
  const year = baseDate.getFullYear()
  const month = String(baseDate.getMonth() + 1).padStart(2, "0")
  const day = String(baseDate.getDate()).padStart(2, "0")
  return `${year}-${month}-${day}`
}

const getCurrentTimeFromBase = (baseDate) => {
  const hours = String(baseDate.getHours()).padStart(2, "0")
  const minutes = String(baseDate.getMinutes()).padStart(2, "0")
  const seconds = String(baseDate.getSeconds()).padStart(2, "0")
  return `${hours}:${minutes}:${seconds}`
}

const isValidHms = (s) => typeof s === "string" && /^\d{2}:\d{2}:\d{2}$/.test(s)
const isValidYmd = (s) => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s)

// Add face verification helper
const euclidean = (a = [], b = []) => {
  if (!a?.length || !b?.length || a.length !== b.length) return Number.POSITIVE_INFINITY
  let s = 0
  for (let i = 0; i < a.length; i++) {
    const d = a[i] - b[i]
    s += d * d
  }
  return Math.sqrt(s)
}

const verifyFaceMatch = (embedding, enrolled, threshold = 0.6) => {
  if (!Array.isArray(embedding) || !embedding.length) return false
  if (!Array.isArray(enrolled) || !enrolled.length) return false
  return euclidean(embedding, enrolled) <= threshold
}

async function findFaceOwner(embedding, excludeUserId) {
  const others = await User.find({ faceEnrolled: true }).select("_id faceEmbedding name email")
  let best = { userId: null, distance: Number.POSITIVE_INFINITY }
  for (const u of others) {
    if (excludeUserId && String(u._id) === String(excludeUserId)) continue
    const d = euclidean(embedding, u.faceEmbedding || [])
    if (d < best.distance) best = { userId: u._id, distance: d }
  }
  return best
}

const _euclid = (a = [], b = []) => {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return Number.POSITIVE_INFINITY
  let s = 0
  for (let i = 0; i < a.length; i++) {
    const d = a[i] - b[i]
    s += d * d
  }
  return Math.sqrt(s)
}
const _matches = (probe = [], enrolled = [], t = 0.6) => _euclid(probe, enrolled) <= t

router.post("/checkin", auth, async (req, res) => {
  try {
    const faceEmbedding = req.body?.faceEmbedding
    if (!Array.isArray(faceEmbedding) || faceEmbedding.length < 64) {
      return res.status(400).json({ message: "Face data is required for check-in." })
    }

    if (!req.user.faceEnrolled || !Array.isArray(req.user.faceEmbedding) || !req.user.faceEmbedding.length) {
      // Inline enroll then proceed with check-in
      req.user.faceEmbedding = faceEmbedding.map(Number)
      req.user.faceEnrolled = true
      req.user.faceModelVersion = "face-api-0.22.2"
      await req.user.save()
    } else {
      // Verify against enrolled face
      if (!_matches(faceEmbedding, req.user.faceEmbedding, 0.6)) {
        return res.status(401).json({ message: "Face did not match your enrolled face." })
      }
    }

    const tzOffsetMinutes = getClientTzOffset(req)

    const { location, clientLocalDate, clientLocalTime, clientTimeZone } = req.body

    const today = isValidYmd(clientLocalDate) ? clientLocalDate : getCurrentDate(tzOffsetMinutes)
    const checkInTime = isValidHms(clientLocalTime) ? clientLocalTime : getCurrentTime(tzOffsetMinutes)

    console.log("[v0] Check-in computed:", {
      source: isValidYmd(clientLocalDate) && isValidHms(clientLocalTime) ? "client-local" : "server-adjusted",
      today,
      checkInTime,
      clientTimeZone,
      tzOffsetMinutes,
    })

    let attendance = await Attendance.findOne({ user: req.user._id, date: today })
    if (attendance?.checkIn) {
      return res.status(400).json({ message: "You have already checked in today", attendance })
    }

    if (!attendance) {
      attendance = new Attendance({ user: req.user._id, date: today })
    }

    attendance.checkIn = checkInTime
    attendance.face = attendance.face || {}
    attendance.face.checkIn = faceEmbedding.map(Number)
    attendance.face.version = "face-api-0.22.2"
    attendance.checkInFaceEmbedding = faceEmbedding.map(Number)
    if (location) {
      attendance.location = attendance.location || {}
      attendance.location.checkIn = JSON.stringify(location)
    }
    await attendance.save()
    await attendance.populate("user", "name employeeId")

    return res.status(200).json({ message: "Checked in successfully.", attendance })
  } catch (error) {
    console.error("Check-in error:", error)
    return res.status(500).json({ error: "Failed to check in. Please try again." })
  }
})

router.post("/checkout", auth, async (req, res) => {
  try {
    const faceEmbedding = req.body?.faceEmbedding
    if (!Array.isArray(faceEmbedding) || faceEmbedding.length < 64) {
      return res.status(400).json({ message: "Face data is required for check-out." })
    }

    if (!req.user.faceEnrolled || !Array.isArray(req.user.faceEmbedding) || !req.user.faceEmbedding.length) {
      return res.status(412).json({ message: "Please enroll your face before checking out." })
    }
    if (!_matches(faceEmbedding, req.user.faceEmbedding, 0.6)) {
      return res.status(401).json({ message: "Face did not match your enrolled face." })
    }

    const tzOffsetMinutes = getClientTzOffset(req)
    const today = getCurrentDate(tzOffsetMinutes)
    const record = await Attendance.findOne({ user: req.user._id, date: today })
    if (!record?.checkIn) {
      return res.status(404).json({ message: "No open check-in found to check out." })
    }
    // Enforce same-face-as-checkin with slightly tighter threshold
    if (Array.isArray(record.checkInFaceEmbedding) && record.checkInFaceEmbedding.length) {
      if (!_matches(faceEmbedding, record.checkInFaceEmbedding, 0.5)) {
        return res.status(401).json({ message: "Face does not match the one used during check-in." })
      }
    }

    const { location, clientLocalDate, clientLocalTime } = req.body
    const checkOutTime = isValidHms(clientLocalTime) ? clientLocalTime : getCurrentTime(tzOffsetMinutes)

    record.checkOut = checkOutTime
    record.face = record.face || {}
    record.face.checkOut = faceEmbedding.map(Number)
    record.checkOutFaceEmbedding = faceEmbedding.map(Number)
    if (location) {
      record.location = record.location || {}
      record.location.checkOut = JSON.stringify(location)
    }
    await record.save()
    await record.populate("user", "name employeeId")

    return res.status(200).json({ message: "Checked out successfully.", attendance: record })
  } catch (error) {
    console.error("Check-out error:", error)
    return res.status(500).json({ error: "Failed to check out. Please try again." })
  }
})

router.get("/status", auth, async (req, res) => {
  try {
    const tzOffsetMinutes = getClientTzOffset(req)
    const today = getCurrentDate(tzOffsetMinutes)
    console.log("Getting status for date:", today, "tzOffset:", tzOffsetMinutes)

    const attendance = await Attendance.findOne({ user: req.user._id, date: today })

    res.json({
      hasCheckedIn: !!attendance?.checkIn,
      hasCheckedOut: !!attendance?.checkOut,
      attendance,
      currentDate: today,
    })
  } catch (error) {
    console.error("Status error:", error)
    res.status(500).json({ error: error.message })
  }
})

router.get("/logs", auth, async (req, res) => {
  try {
    const tzOffsetMinutes = getClientTzOffset(req)
    const { page = 1, limit = 10, userId, date } = req.query
    const today = getCurrentDate(tzOffsetMinutes)
    const targetDate = date || today

    console.log("Fetching logs for date:", targetDate, "tzOffset:", tzOffsetMinutes)

    const query = {}

    if (req.user.role === "employee") {
      query.user = req.user._id
    } else if (userId) {
      query.user = userId
    }

    query.date = targetDate

    let allUsers = []
    if (req.user.role !== "employee") {
      const userQuery = { isActive: true }
      if (userId) {
        userQuery._id = userId
      }
      allUsers = await User.find(userQuery).select("_id name employeeId department position")
    }

    const attendanceRecords = await Attendance.find(query)
      .populate("user", "name employeeId department position")
      .sort({ createdAt: -1 })

    // Leave lookups use the provided date; no TZ change needed here.
    const leaveQuery = {
      status: "approved",
      startDate: { $lte: new Date(targetDate) },
      endDate: { $gte: new Date(targetDate) },
    }
    const leaveRecords = await Leave.find(leaveQuery).populate("user", "name employeeId department position")

    // Create comprehensive logs
    let logs = []

    if (req.user.role === "employee") {
      // For employees, just return their attendance records
      logs = attendanceRecords
    } else {
      // For admin/manager, create comprehensive view
      // Create a map of user attendance for the target date
      const attendanceMap = new Map()
      attendanceRecords.forEach((record) => {
        attendanceMap.set(record.user._id.toString(), record)
      })

      // Create a map of users on leave for the target date
      const leaveMap = new Map()
      leaveRecords.forEach((leave) => {
        leaveMap.set(leave.user._id.toString(), leave)
      })

      // Build comprehensive logs for all users
      allUsers.forEach((user) => {
        const userId = user._id.toString()
        const attendance = attendanceMap.get(userId)
        const leave = leaveMap.get(userId)

        if (attendance) {
          logs.push(attendance)
        } else if (leave) {
          // Create a virtual attendance record for leave
          logs.push({
            _id: `leave_${userId}_${targetDate}`,
            user: user,
            date: targetDate,
            checkIn: null,
            checkOut: null,
            workingHours: 0,
            status: "on_leave",
            leaveType: leave.leaveType,
            leaveReason: leave.reason,
            isLeave: true,
          })
        } else {
          // Create a virtual attendance record for absent
          logs.push({
            _id: `absent_${userId}_${targetDate}`,
            user: user,
            date: targetDate,
            checkIn: null,
            checkOut: null,
            workingHours: 0,
            status: "absent",
            isAbsent: true,
          })
        }
      })

      // Sort logs by user name
      logs.sort((a, b) => {
        const nameA = a.user?.name || ""
        const nameB = b.user?.name || ""
        return nameA.localeCompare(nameB)
      })
    }

    // Apply pagination
    const startIndex = (page - 1) * limit
    const endIndex = startIndex + Number.parseInt(limit)
    const paginatedLogs = logs.slice(startIndex, endIndex)

    const total = logs.length

    res.json({
      logs: paginatedLogs,
      totalPages: Math.ceil(total / limit),
      currentPage: Number.parseInt(page),
      total,
      currentDate: targetDate,
    })
  } catch (error) {
    console.error("Attendance logs error:", error)
    res.status(500).json({ error: error.message })
  }
})

// FIXED: Stats calculation with proper date range and working hours
router.get("/stats", auth, async (req, res) => {
  try {
    const tzOffsetMinutes = getClientTzOffset(req)
    const { month, year } = req.query
    const localNow = getLocalNow(tzOffsetMinutes)
    const targetMonth = Number(month) || localNow.getMonth() + 1
    const targetYear = Number(year) || localNow.getFullYear()

    console.log(`Calculating stats for ${targetYear}-${targetMonth} tzOffset:`, tzOffsetMinutes)

    const query = { user: req.user._id }
    const startDate = `${targetYear}-${String(targetMonth).padStart(2, "0")}-01`
    const lastDay = new Date(targetYear, targetMonth, 0).getDate()
    const endDate = `${targetYear}-${String(targetMonth).padStart(2, "0")}-${String(lastDay).padStart(2, "0")}`
    query.date = { $gte: startDate, $lte: endDate }

    const attendanceRecords = await Attendance.find(query)

    const stats = {
      totalDays: attendanceRecords.length,
      presentDays: attendanceRecords.filter((r) => r.checkIn).length,
      totalHours: 0,
      averageHours: 0,
      lateCount: 0,
    }

    attendanceRecords.forEach((record) => {
      if (record.workingHours && record.workingHours > 0) {
        stats.totalHours += record.workingHours
      }
    })

    stats.totalHours = Math.round(stats.totalHours * 100) / 100
    if (stats.presentDays > 0) {
      stats.averageHours = Math.round((stats.totalHours / stats.presentDays) * 100) / 100
    }

    res.json(stats)
  } catch (error) {
    console.error("Stats calculation error:", error)
    res.status(500).json({ error: error.message })
  }
})

// Generate attendance report
router.get("/report", auth, managerAuth, async (req, res) => {
  try {
    const { startDate, endDate, userId } = req.query

    if (!startDate || !endDate) {
      return res.status(400).json({ error: "Start date and end date are required" })
    }

    const query = {
      date: { $gte: startDate, $lte: endDate },
    }

    // Admin/Manager/HR can get reports for all users or a specific user
    if (req.user.role === "admin" || req.user.role === "manager" || req.user.role === "hr") {
      if (userId) {
        query.user = userId
      }
      // If userId is not provided, no user filter is applied, fetching for all
    } else {
      // Employee can only get reports for themselves
      query.user = req.user._id
    }

    const report = await Attendance.find(query)
      .populate("user", "name employeeId department position")
      .sort({ date: -1, "user.name": 1 })

    res.json({
      report,
      dateRange: { startDate, endDate },
      totalRecords: report.length,
    })
  } catch (error) {
    console.error("Report generation error:", error)
    res.status(500).json({ error: error.message })
  }
})

// ENHANCED: Download attendance report with better Excel presentation
router.get("/download-report", auth, managerAuth, async (req, res) => {
  try {
    const { startDate, endDate, userId } = req.query

    console.log("Download report request:", { startDate, endDate, userId })

    if (!startDate || !endDate) {
      return res.status(400).json({ error: "Start date and end date are required" })
    }

    const query = {
      date: { $gte: startDate, $lte: endDate },
    }

    // Admin/Manager/HR can get reports for all users or a specific user
    if (req.user.role === "admin" || req.user.role === "manager" || req.user.role === "hr") {
      if (userId) {
        query.user = userId
      }
      // If userId is not provided, no user filter is applied, fetching for all
    } else {
      // Employee can only get reports for themselves
      query.user = req.user._id
    }

    console.log("Query:", query)

    const report = await Attendance.find(query)
      .populate("user", "name employeeId department position")
      .sort({ date: -1, "user.name": 1 })

    console.log(`Found ${report.length} records for report`)

    if (report.length === 0) {
      return res.status(404).json({ error: "No attendance records found for the specified date range" })
    }

    // Helper function to format time for display
    const formatTime = (time) => {
      if (!time) return ""
      try {
        const [hours, minutes] = time.split(":")
        const hour12 =
          Number.parseInt(hours) === 0
            ? 12
            : Number.parseInt(hours) > 12
              ? Number.parseInt(hours) - 12
              : Number.parseInt(hours)
        const ampm = Number.parseInt(hours) >= 12 ? "PM" : "AM"
        return `${hour12}:${minutes} ${ampm}`
      } catch (error) {
        console.error("Error formatting time:", error)
        return time
      }
    }

    // Helper function to format date
    const formatDate = (dateString) => {
      try {
        const date = new Date(dateString + "T00:00:00")
        return date.toLocaleDateString("en-US", {
          year: "numeric",
          month: "short",
          day: "numeric",
          weekday: "short",
        })
      } catch (error) {
        console.error("Error formatting date:", error)
        return dateString
      }
    }

    // ENHANCED: Create report header with better presentation
    const reportTitle = "EMPLOYEE ATTENDANCE REPORT"
    const companyName = "Employee Attendance Management System"
    const reportDate = new Date().toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    })

    // Get employee name for report
    const employeeName = userId ? (report.length > 0 ? report[0].user?.name : "Unknown Employee") : "All Employees"

    // ENHANCED: Report header section with better formatting
    let csvContent = ""

    // Title section
    csvContent += `${reportTitle}\n`
    csvContent += `${companyName}\n`
    csvContent += `Generated on: ${reportDate}\n`
    csvContent += `Report Period: ${formatDate(startDate)} to ${formatDate(endDate)}\n`
    csvContent += `Employee(s): ${employeeName}\n`
    csvContent += `Generated by: ${req.user.name} (${req.user.employeeId})\n`
    csvContent += "\n"

    // ENHANCED: Data table with better headers (removed Notes column)
    const csvHeader =
      [
        "EMPLOYEE NAME",
        "EMPLOYEE ID",
        "DEPARTMENT",
        "POSITION",
        "DATE",
        "DAY OF WEEK",
        "CHECK IN TIME",
        "CHECK OUT TIME",
        "WORKING HOURS",
        "STATUS",
      ].join(",") + "\n"

    csvContent += csvHeader

    // Add separator line
    csvContent += Array(10).fill('""').join(",") + "\n"

    // Data rows
    report.forEach((record) => {
      try {
        const status = record.checkIn && record.checkOut ? "Complete" : record.checkIn ? "Incomplete" : "Absent"
        const workingHours = record.workingHours > 0 ? record.workingHours.toFixed(2) : "0.00"
        const formattedDate = formatDate(record.date)
        const dayOfWeek = new Date(record.date + "T00:00:00").toLocaleDateString("en-US", { weekday: "long" })

        const row = [
          `"${record.user?.name || ""}"`,
          `"${record.user?.employeeId || ""}"`,
          `"${record.user?.department || ""}"`,
          `"${record.user?.position || ""}"`,
          `"${formattedDate}"`,
          `"${dayOfWeek}"`,
          `"${formatTime(record.checkIn)}"`,
          `"${formatTime(record.checkOut)}"`,
          `"${workingHours}"`,
          `"${status}"`,
        ].join(",")

        csvContent += row + "\n"
      } catch (error) {
        console.error("Error processing record:", error, record)
      }
    })

    // ENHANCED: Summary statistics section with better presentation
    const totalRecords = report.length
    const totalHours = report.reduce((sum, r) => sum + (r.workingHours || 0), 0)
    const completeRecords = report.filter((r) => r.checkIn && r.checkOut).length
    const incompleteRecords = report.filter((r) => r.checkIn && !r.checkOut).length
    const absentRecords = report.filter((r) => !r.checkIn).length
    const avgHours = totalRecords > 0 ? (totalHours / totalRecords).toFixed(2) : "0.00"
    const avgCompleteHours = completeRecords > 0 ? (totalHours / completeRecords).toFixed(2) : "0.00"

    // Add spacing before summary
    csvContent += "\n"

    // Summary section with enhanced formatting
    csvContent += `ATTENDANCE SUMMARY STATISTICS\n`
    csvContent += Array(10).fill('""').join(",") + "\n"

    csvContent += `METRIC,VALUE,PERCENTAGE\n`
    csvContent += `Total Records,${totalRecords},100.00%\n`
    csvContent += `Complete Records,${completeRecords},${((completeRecords / totalRecords) * 100).toFixed(2)}%\n`
    csvContent += `Incomplete Records,${incompleteRecords},${((incompleteRecords / totalRecords) * 100).toFixed(2)}%\n`
    csvContent += `Absent Records,${absentRecords},${((absentRecords / totalRecords) * 100).toFixed(2)}%\n`
    csvContent += "\n"

    csvContent += `WORKING HOURS ANALYSIS\n`
    csvContent += Array(10).fill('""').join(",") + "\n"
    csvContent += `Total Working Hours,${totalHours.toFixed(2)} hours,\n`
    csvContent += `Average Hours per Record,${avgHours} hours,\n`
    csvContent += `Average Hours (Complete Records Only),${avgCompleteHours} hours,\n`
    csvContent += `Maximum Possible Hours,${(totalRecords * 8).toFixed(2)} hours,(Assuming 8 hrs/day)\n`
    csvContent += `Productivity Rate,${((totalHours / (totalRecords * 8)) * 100).toFixed(2)}%,(Actual vs Maximum)\n`
    csvContent += "\n"

    csvContent += `ADDITIONAL INFORMATION\n`
    csvContent += Array(10).fill('""').join(",") + "\n"
    csvContent += `Report Generated By,${req.user.name},${req.user.role}\n`
    csvContent += `Generation Date,${new Date().toLocaleString()},\n`
    csvContent += `System,Employee Attendance Management,v1.0\n`

    console.log("Enhanced CSV generated successfully, length:", csvContent.length)

    // Set proper headers for CSV download
    res.setHeader("Content-Type", "text/csv; charset=utf-8")
    res.setHeader("Content-Disposition", `attachment; filename="Attendance_Report_${startDate}_to_${endDate}.csv"`)
    res.setHeader("Content-Length", Buffer.byteLength(csvContent, "utf8"))

    // Send the CSV data
    res.status(200).send(csvContent)
  } catch (error) {
    console.error("Download report error:", error)
    res.status(500).json({ error: "Failed to generate report: " + error.message })
  }
})

module.exports = router
