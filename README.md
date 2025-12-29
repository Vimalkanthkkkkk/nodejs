# Backend + WebSocket - Live Attendance System

**Tech Stack:** Node.js, Express, MongoDB, Mongoose, JWT, bcrypt, `ws` (WebSocket)

---

## Overview

Build a complete backend system with:

- Authentication (signup, login, me)
- Role-based access control (teacher & student)
- Class management CRUD
- WebSocket-based live attendance
- Attendance persistence to MongoDB

**Key Assumption:** Only **ONE class session** can be active at a time on WebSocket. No room management needed - all broadcasts go to all connected clients.
