const roles = ["admin", "manager", "hr", "employee"]
const clientsByRole = roles.reduce((acc, r) => {
  acc[r] = new Set()
  return acc
}, {})

/**
 * Register an SSE client for a role
 */
function addClient(role, res) {
  if (!clientsByRole[role]) return
  clientsByRole[role].add(res)
}

/**
 * Remove an SSE client for a role
 */
function removeClient(role, res) {
  if (!clientsByRole[role]) return
  clientsByRole[role].delete(res)
}

/**
 * Broadcast a payload to all connected clients for the given roles
 */
function broadcastToRoles(targetRoles, payload) {
  try {
    const data = `event: notification\ndata: ${JSON.stringify(payload)}\n\n`
    targetRoles.forEach((r) => {
      const set = clientsByRole[r]
      if (!set) return
      for (const res of set) {
        try {
          res.write(data)
        } catch (err) {
          // Best-effort; drop broken connections
          try {
            set.delete(res)
          } catch {}
        }
      }
    })
  } catch (e) {
    console.error("[v0] Realtime broadcast error:", e)
  }
}

module.exports = {
  addClient,
  removeClient,
  broadcastToRoles,
}
