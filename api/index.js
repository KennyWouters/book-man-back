import express from "express";
import pkg from 'pg';
const { Pool } = pkg; // Replace sqlite3 with pg
import bodyParser from "body-parser";
import cors from "cors";
import cron from "node-cron";
import { sendEmail } from "../email.js";
import * as path from "node:path"; // Import the email utility
import session from "express-session";
import bcrypt from "bcryptjs";
import cookieParser from 'cookie-parser';
// import { Pool } from 'pg';

import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = 3001;

// Trust proxy (needed for secure cookies)
app.set('trust proxy', 1);

// Create a new MemoryStore instance
const store = new session.MemoryStore();

// Basic middleware
app.use(bodyParser.json());
app.use(cookieParser('your-secret-key'));

// Session configuration BEFORE CORS
app.use(
    session({
        secret: 'your-secret-key',
        store: store,
        name: 'connect.sid',
        resave: true,
        saveUninitialized: false,
        proxy: true,
        cookie: {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            path: '/',
            maxAge: 24 * 60 * 60 * 1000
        }
    })
);

// CORS configuration AFTER session
const allowedOrigins = [
    'https://book-man-swart.vercel.app',
    'https://book-man-b65d9d654296.herokuapp.com',
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:3000',
    'http://localhost:3001'
];

// Configure CORS middleware with more detailed options
const corsOptions = {
    origin: function (origin, callback) {
        console.log('Request origin:', origin);
        
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) {
            console.log('Allowing request with no origin');
            return callback(null, true);
        }
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            console.log('Allowing request from origin:', origin);
            callback(null, true);
        } else {
            console.log('Blocking request from unauthorized origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'Access-Control-Request-Method', 'Access-Control-Request-Headers', 'Cookie'],
    exposedHeaders: ['Set-Cookie'],
    preflightContinue: false,
    optionsSuccessStatus: 204
};

// Apply CORS middleware to all routes with options
app.use(cors(corsOptions));

// Handle preflight requests for all routes
app.options('*', cors(corsOptions));

// Additional headers middleware for extra security
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        // Set CORS headers
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
        res.header('Access-Control-Expose-Headers', 'Set-Cookie');
        res.header('Vary', 'Origin');
    }
    next();
});

// Add the hello endpoint back
app.get("/api/hello", (req, res) => {
    res.set('Content-Type', 'application/json');
    res.json({ message: "Hello, World!" });
});

// Debug middleware to log all requests
app.use((req, res, next) => {
    console.log('\n=== Request Debug ===');
    console.log('Method:', req.method);
    console.log('URL:', req.url);
    console.log('Origin:', req.headers.origin);
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    next();
});

// Middleware to check if an admin is authenticated
const isAdminAuthenticated = (req, res, next) => {
    console.log('Checking authentication...');
    console.log('Session:', req.session);
    console.log('Session ID:', req.session.id);
    console.log('AdminId:', req.session.adminId);
    console.log('FirstName:', req.session.firstName);
    console.log('Cookies:', req.cookies);
    console.log('Store contents:', store.sessions);

    if (!req.session) {
        console.log('No session found');
        return res.status(403).json({ error: "No session found" });
    }

    if (!req.session.adminId) {
        console.log('No adminId in session');
        return res.status(403).json({ error: "Not authenticated" });
    }

    console.log('Authentication successful');
    next();
};

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

pool.connect()
    .then(() => console.log("Connected to Heroku PostgreSQL"))
    .catch((err) => console.error("Error connecting to Heroku PostgreSQL:", err));


const createTables = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS bookings (
                                                    id SERIAL PRIMARY KEY,
                                                    phone_number TEXT NOT NULL,
                                                    first_name TEXT NOT NULL,
                                                    last_name TEXT NOT NULL,
                                                    day DATE NOT NULL,
                                                    start_hour INTEGER NOT NULL,
                                                    end_hour INTEGER NOT NULL,
                                                    role TEXT DEFAULT 'user'
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS notifications (
                                                         id SERIAL PRIMARY KEY,
                                                         email TEXT NOT NULL,
                                                         day DATE NOT NULL,
                                                         UNIQUE(email, day)
                )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS admins (
                                                  id SERIAL PRIMARY KEY,
                                                  first_name TEXT NOT NULL,
                                                  password_hash TEXT NOT NULL
            )
        `);

        await pool.query(`
        CREATE TABLE IF NOT EXISTS "AvailabilityStatus" (
            "id" SERIAL PRIMARY KEY,
            "targetDate" DATE UNIQUE NOT NULL,
            "status" BOOLEAN NOT NULL DEFAULT false,
            "comment" TEXT
);
        `)

        console.log("Tables created or already exist.");
    } catch (err) {
        console.error("Error creating tables:", err);
    }
};

createTables();

// Helper function to get the Monday of the current week
const getMondayOfCurrentWeek = () => {
    const today = new Date();
    const dayOfWeek = today.getDay(); // 0 (Sunday) to 6 (Saturday)
    const monday = new Date(today);
    monday.setDate(today.getDate() - (dayOfWeek === 0 ? 6 : dayOfWeek -1)); // Adjust to Monday
    monday.setHours(0, 0, 0, 0); // Normalize time to midnight
    return monday;
};

// API to fetch calendar dates (from Monday of the current week to Sunday of the next week)


// Initialize startDate to the Monday of the current week
let startDate = getMondayOfCurrentWeek();

// Schedule a task to reset startDate every two weeks
cron.schedule('0 0 * * 1', () => {
    const today = new Date();
    const dayOfWeek = today.getDay();
    const weeksSinceStart = Math.floor((today - startDate) / (1000 * 60 * 60 * 24 * 7));

    // Reset startDate if two weeks have passed
    if (weeksSinceStart >= 2) {
        startDate = getMondayOfCurrentWeek();
        console.log("Start date reset to:", startDate);
    }
});

// API to fetch calendar dates (from startDate to two weeks later)
// app.get("/api/dates", (req, res) => {
//     const dates = Array.from({ length: 14 }, (_, i) => {
//         const date = new Date(startDate);
//         date.setDate(startDate.getDate() + i);
//         return date.toISOString().split("T")[0]; // Format as YYYY-MM-DD
//     });
//     res.json(dates);
// });

app.get("/api/dates", async (req, res) => {
    const monday = await getMondayBeforeEndDate();
    const dates = Array.from({ length: 14 }, (_, i) => {
        const date = new Date(monday);
        date.setDate(monday.getDate() + i);
        return date.toISOString().split("T")[0];
    });
    res.json(dates);
});

// API to save a booking
app.post("/api/book", async (req, res) => {
    const { phoneNumber, firstName, lastName, day, startHour, endHour } = req.body;

    try {
        // Check the number of existing bookings for the given day
        const countQuery = await pool.query(
            `SELECT COUNT(*) as count FROM bookings WHERE day = $1`,
            [day]
        );

        if (countQuery.rows[0].count >= 10) {
            return res.status(400).json({ error: "Maximum bookings reached for this date" });
        }

        // Insert the new booking
        const insertQuery = await pool.query(
            `INSERT INTO bookings (phone_number, first_name, last_name, day, start_hour, end_hour)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
            [phoneNumber, firstName, lastName, day, startHour, endHour]
        );

        res.json({ id: insertQuery.rows[0].id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Add the hello endpoint back
/*app.get("/api/hello", (req, res) => {
    res.set('Content-Type', 'application/json');
    res.json({ message: "Hello, World!" });
});*/


// API to check if a date is fully booked
app.get("/api/availability/:day", async (req, res) => {
    const { day } = req.params;

    try {
        const countQuery = await pool.query(
            `SELECT COUNT(*) as count FROM bookings WHERE day = $1`,
            [day]
        );

        const isFullyBooked = countQuery.rows[0].count >= 10;
        res.json({ isFullyBooked });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API to subscribe for notifications
app.post("/api/notify", async (req, res) => {
    const { email, day } = req.body;

    try {
        const insertQuery = await pool.query(
            `INSERT INTO notifications (email, day) VALUES ($1, $2)`,
            [email, day]
        );

        res.json({ message: "You will be notified when this date becomes available." });
    } catch (err) {
        if (err.code === "23505") { // Unique constraint violation
            res.status(400).json({ error: "You are already subscribed for notifications for this date." });
        } else {
            res.status(500).json({ error: err.message });
        }
    }
});

// Function to notify users when a date becomes available
const notifyUsers = async (day) => {
    try {
        const notificationsQuery = await pool.query(
            `SELECT email FROM notifications WHERE day = $1`,
            [day]
        );

        for (const row of notificationsQuery.rows) {
            const { email } = row;
            const subject = "Une place s'est libérée à l'atelier bois !";
            const formattedDay = new Date(day).toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' });
            const text = `Bonjour, une place s'est libérée pour le ${formattedDay}. Réservez vite !`;

            await sendEmail(email, subject, text);

            // Optionally, delete the notification after sending the email
            await pool.query(
                `DELETE FROM notifications WHERE email = $1 AND day = $2`,
                [email, day]
            );
        }
    } catch (error) {
        console.error("Error notifying users:", error);
    }
};

// Call this function when a booking is canceled
app.delete("/api/bookings/:id", async (req, res) => {
    const { id } = req.params;

    try {
        const deleteQuery = await pool.query(
            `DELETE FROM bookings WHERE id = $1 RETURNING day`,
            [id]
        );

        if (deleteQuery.rows.length > 0) {
            const { day } = deleteQuery.rows[0];

            // Check if the date is now available
            const countQuery = await pool.query(
                `SELECT COUNT(*) as count FROM bookings WHERE day = $1`,
                [day]
            );

            if (countQuery.rows[0].count < 10) {
                await notifyUsers(day);
            }
        }

        res.json({ message: "Booking deleted successfully." });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Serve the admin login page (no authentication required)
app.get("/admin", (req, res) => {
    res.sendFile(path.join(__dirname, "admin", "admin-login.jsx"));
});

// Updated login endpoint
app.post("/admin/login", async (req, res) => {
    console.log('Login attempt:', req.body);
    const { firstName, password } = req.body;
    
    if (!firstName || !password) {
        return res.status(400).json({ error: "Missing credentials" });
    }

    try {
        const adminQuery = await pool.query(
            `SELECT * FROM admins WHERE first_name = $1`,
            [firstName]
        );

        if (adminQuery.rows.length === 0) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const admin = adminQuery.rows[0];
        const isPasswordValid = await bcrypt.compare(password, admin.password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // Set session data
        req.session.adminId = admin.id;
        req.session.firstName = admin.first_name;
        req.session.isAdmin = true;
        req.session.lastAccess = Date.now();

        // Save session explicitly
        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) {
                    console.error('Session save error:', err);
                    reject(err);
                    return;
                }
                resolve();
            });
        });

        console.log('Login successful, session saved:', {
            sessionId: req.sessionID,
            adminId: req.session.adminId,
            firstName: req.session.firstName,
            cookie: req.session.cookie
        });

        res.json({ 
            adminId: admin.id,
            firstName: admin.first_name,
            message: "Login successful"
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Updated protection middleware
const protectAdminRoutes = async (req, res, next) => {
    console.log('=== Protection Middleware ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session Data:', req.session);
    console.log('Store contents:', Object.keys(store.sessions).length, 'sessions');

    if (!req.session) {
        console.log('No session found');
        return res.status(403).json({ error: "No session found" });
    }

    if (!req.session.adminId || !req.session.firstName) {
        console.log('Missing admin session data');
        return res.status(403).json({ error: "Please log in as admin" });
    }

    try {
        // Update last access time
        req.session.lastAccess = Date.now();
        
        // Verify admin exists in database
        const adminQuery = await pool.query(
            `SELECT id, first_name FROM admins WHERE id = $1`,
            [req.session.adminId]
        );

        if (adminQuery.rows.length === 0) {
            console.log('Admin not found in database');
            req.session.destroy();
            return res.status(403).json({ error: "Invalid admin session" });
        }

        next();
    } catch (err) {
        console.error('Admin verification error:', err);
        return res.status(500).json({ error: "Authentication error" });
    }
};

// Update protected routes to use new middleware
app.get("/api/admin/name", protectAdminRoutes, async (req, res) => {
    res.json({ name: req.session.firstName });
});

app.get('/api/admin/bookings', protectAdminRoutes, async (req, res) => {
    const { day } = req.query;

    if (!day) {
        return res.status(400).json({ error: 'Day parameter is required' });
    }
    try {
        const bookingsQuery = await pool.query(
            `SELECT * FROM bookings WHERE day = $1`,
            [day]
        );
        res.json(bookingsQuery.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get("/admin/dashboard", protectAdminRoutes, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin-dashboard.html"));
});

// Update logout endpoint
app.get("/admin/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
            return res.status(500).json({ error: "Could not log out" });
        }
        res.clearCookie("connect.sid");
        res.json({ message: "Logged out successfully" });
    });
});

cron.schedule("0 0 * * 1", async () => {
    try {
        const endDateResult = await pool.query('SELECT end_date FROM end_date LIMIT 1');
        if (endDateResult.rows.length === 0) return;

        const currentEndDate = new Date(endDateResult.rows[0].end_date);
        const today = new Date();

        if (currentEndDate < today) {
            const newEndDate = new Date(currentEndDate);
            newEndDate.setDate(currentEndDate.getDate() + 14);

            await client.query('UPDATE end_date SET end_date = $1', [newEndDate.toISOString().split('T')[0]]);
            console.log(`End date updated to ${newEndDate.toISOString().split('T')[0]}`);
        }
    } catch (err) {
        console.error("Error updating end date:", err);
    }
});


const getMondayBeforeEndDate = async () => {
    try {
        const result = await pool.query('SELECT end_date FROM end_date LIMIT 1');
        if (result.rows.length === 0) return getMondayOfCurrentWeek();

        const endDate = new Date(result.rows[0].end_date);
        const twoWeeksBeforeEnd = new Date(endDate);
        twoWeeksBeforeEnd.setDate(endDate.getDate() - 13);

        const dayOfWeek = twoWeeksBeforeEnd.getDay();
        if (dayOfWeek !== 1) {
            twoWeeksBeforeEnd.setDate(twoWeeksBeforeEnd.getDate() - (dayOfWeek === 0 ? 6 : dayOfWeek - 1));
        }

        twoWeeksBeforeEnd.setHours(0, 0, 0, 0);
        return twoWeeksBeforeEnd;
    } catch (err) {
        console.error("Error getting end date:", err);
        return getMondayOfCurrentWeek(); // Fallback
    }
};

// API endpoint for creating or updating availability status
app.post("/api/admin/availability-status", async (req, res) => {
    const { date, status, comment } = req.body;

    // Validate required fields
    if (!date) {
        return res.status(400).json({ error: "Date is required" });
    }

    if (typeof status !== 'boolean') {
        return res.status(400).json({ error: "Status must be a boolean value" });
    }

    try {
        // Check if the exact same record already exists
        const checkQuery = await pool.query(
            `SELECT * FROM "AvailabilityStatus" WHERE "targetDate" = $1 AND "status" = $2 AND "comment" = $3`,
            [date, status, comment]
        );

        if (checkQuery.rows.length > 0) {
            return res.json({
                success: false,
                message: "Availability status already set to the same values"
            });
        }

        // Insert or update the availability status
        const result = await pool.query(
            `INSERT INTO "AvailabilityStatus" ("targetDate", "status", "comment")
             VALUES ($1, $2, $3)
             ON CONFLICT ("targetDate") 
             DO UPDATE SET
                "status" = $2,
                "comment" = $3
             RETURNING *`,
            [date, status, comment]
        );

        res.json({
            success: true,
            message: "Availability status updated successfully",
            data: result.rows[0]
        });
    } catch (err) {
        console.error("Error updating availability status:", err);
        res.status(500).json({ error: err.message });
    }
});;

// API endpoint for retrieving availability status
app.get("/api/availability-status/:date", async (req, res) => {
    const { date } = req.params;
    
    try {
        const result = await pool.query(
            `SELECT * FROM "AvailabilityStatus" WHERE "targetDate" = $1`,
            [date]
        );
        
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.json({ 
                targetDate: date,
                status: false, // Default status
                comment: null
            });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API endpoint for retrieving all availability statuses
app.get("/api/admin/availability-status", async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM "AvailabilityStatus" ORDER BY "targetDate"`
        );
        
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API endpoint for modifying existing availability status
app.put("/api/admin/availability-status/:date", async (req, res) => {
    const { date } = req.params;
    const { status, comment } = req.body;
    
    // Validate required fields
    if (typeof status !== 'boolean') {
        return res.status(400).json({ error: "Status must be a boolean value" });
    }
    
    try {
        // Check if the record exists first
        const checkResult = await pool.query(
            `SELECT * FROM "AvailabilityStatus" WHERE "targetDate" = $1`,
            [date]
        );
        
        if (checkResult.rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: "No availability status found for the specified date" 
            });
        }
        
        // Update the existing record
        const result = await pool.query(
            `UPDATE "AvailabilityStatus" 
             SET "status" = $2, "comment" = $3
             WHERE "targetDate" = $1
             RETURNING *`,
            [date, status, comment]
        );
        
        res.json({ 
            success: true, 
            message: "Availability status updated successfully",
            data: result.rows[0]
        });
    } catch (err) {
        console.error("Error updating availability status:", err);
        res.status(500).json({ error: err.message });
    }
});

// Session cleanup interval (every 15 minutes)
setInterval(() => {
    const now = Date.now();
    store.all((err, sessions) => {
        if (err) {
            console.error('Session cleanup error:', err);
            return;
        }
        
        Object.keys(sessions).forEach(sid => {
            const session = sessions[sid];
            const lastAccess = session.lastAccess || 0;
            
            // Remove sessions older than 24 hours or without admin data
            if (now - lastAccess > 24 * 60 * 60 * 1000 || !session.adminId) {
                store.destroy(sid, (err) => {
                    if (err) console.error('Error destroying session:', err);
                });
            }
        });
    });
}, 15 * 60 * 1000);

// Start the server
const PORT = process.env.PORT || 5432;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// const password = "admin123"; // Replace with the desired password
// const saltRounds = 10;
// const hash = await bcrypt.hash(password, saltRounds);
// console.log(hash); // Use this hash in the INSERT query