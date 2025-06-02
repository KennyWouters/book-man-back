import express from "express";
import pkg from 'pg';
const { Pool } = pkg; // Replace sqlite3 with pg
import bodyParser from "body-parser";
import cors from "cors";
import { sendEmail } from "../email.js"; // Fix the path
import * as path from "node:path"; // Import the email utility
import session from "express-session";
import bcrypt from "bcryptjs";
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
// import { Pool } from 'pg';

import { fileURLToPath } from 'url';
import { dirname } from 'path';

// Load environment variables
dotenv.config();

// Log environment for debugging
console.log('Environment:', {
    NODE_ENV: process.env.NODE_ENV,
    DATABASE_URL: process.env.DATABASE_URL ? 'Set' : 'Not set',
    PORT: process.env.PORT || 3001
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = process.env.PORT || 3001;

// Define allowed origins first
const allowedOrigins = [
    'https://book-man-swart.vercel.app',
    'https://book-man-b65d9d654296.herokuapp.com',
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:3000',
    'http://localhost:3001'
];

// Configure CORS middleware
const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'Cookie'],
    exposedHeaders: ['set-cookie']
};

app.use(cors(corsOptions));

// Basic middleware
app.use(bodyParser.json());
app.use(cookieParser());

// Create a new MemoryStore instance
const store = new session.MemoryStore();

// Session configuration
app.use(
    session({
        secret: process.env.SESSION_SECRET || 'your-secret-key',
        store: store,
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none',
            maxAge: 24 * 60 * 60 * 1000,
            path: '/',
            domain: process.env.NODE_ENV === 'production' ? '.herokuapp.com' : undefined
        }
    })
);

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
    console.log('=== Authentication Debug ===');
    console.log('Session:', req.session);
    console.log('Cookies:', req.cookies);
    console.log('Headers:', req.headers);

    if (!req.session || !req.session.adminId) {
        console.log('Authentication failed - No session or adminId');
        return res.status(403).json({ 
            error: "Not authenticated",
            debug: {
                hasSession: !!req.session,
                hasAdminId: req.session ? !!req.session.adminId : false
            }
        });
    }

    next();
};

// Configure database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Test database connection before starting server
const startServer = async () => {
    try {
        // Test database connection
        await pool.connect();
        console.log("Connected to PostgreSQL database");

        // Create tables after successful connection
        await createTables();

        // Start the server only after database is connected
        app.listen(port, () => {
            console.log(`Server running on port ${port}`);
        });
    } catch (err) {
        console.error("Database connection error:", err);
        process.exit(1); // Exit if we can't connect to the database
    }
};

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
            )
        `);

        // Add end_date table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS end_date (
                id SERIAL PRIMARY KEY,
                end_date DATE NOT NULL
            )
        `);

        // Initialize end_date if empty
        const endDateCheck = await pool.query('SELECT * FROM end_date LIMIT 1');
        if (endDateCheck.rows.length === 0) {
            const initialEndDate = new Date();
            initialEndDate.setDate(initialEndDate.getDate() + 14);
            await pool.query('INSERT INTO end_date (end_date) VALUES ($1)', [initialEndDate.toISOString().split('T')[0]]);
        }

        console.log("Tables created or already exist.");
    } catch (err) {
        console.error("Error creating tables:", err);
    }
};

// Start the server
startServer();

// Helper function to get the Monday of the current week
const getMondayOfCurrentWeek = () => {
    const today = new Date();
    const dayOfWeek = today.getDay(); // 0 (Sunday) to 6 (Saturday)
    const monday = new Date(today);
    monday.setDate(today.getDate() - (dayOfWeek === 0 ? 6 : dayOfWeek -1)); // Adjust to Monday
    monday.setHours(0, 0, 0, 0); // Normalize time to midnight
    return monday;
};

// Initialize startDate to the Monday of the current week
let startDate = getMondayOfCurrentWeek();

// Schedule task to reset startDate every two weeks (14 days)
setInterval(() => {
    const today = new Date();
    const weeksSinceStart = Math.floor((today - startDate) / (1000 * 60 * 60 * 24 * 7));

    if (weeksSinceStart >= 2) {
        startDate = getMondayOfCurrentWeek();
        console.log("Start date reset to:", startDate);
    }
}, 24 * 60 * 60 * 1000); // Check once per day

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
        // Check if this phone number already has a booking for this date
        const existingBookingQuery = await pool.query(
            `SELECT id FROM bookings 
             WHERE phone_number = $1 
             AND day = $2`,
            [phoneNumber, day]
        );

        if (existingBookingQuery.rows.length > 0) {
            return res.status(400).json({ 
                error: "This phone number already has a booking for this date"
            });
        }

        // Check the number of existing bookings for the given day
        const countQuery = await pool.query(
            `SELECT COUNT(*) as count FROM bookings WHERE day = $1`,
            [day]
        );

        if (countQuery.rows[0].count >= 10) {
            return res.status(400).json({ 
                error: "Maximum bookings reached for this date" 
            });
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
    console.log('Login attempt:', {
        body: req.body,
        headers: req.headers
    });
    
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

        // Set a custom header to confirm session creation
        res.set('X-Session-Created', 'true');
        
        res.json({ 
            success: true,
            adminId: admin.id,
            firstName: admin.first_name,
            message: "Login successful",
            sessionId: req.sessionID
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
app.get("/api/admin/name",  async (req, res) => {
    res.json({ name: req.session.firstName });
});

app.get('/api/admin/bookings', async (req, res) => {
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

app.get("/admin/dashboard",  (req, res) => {
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

/*// Automatic end date update
setInterval(async () => {
    try {
        const endDateResult = await pool.query('SELECT end_date FROM end_date LIMIT 1');
        if (endDateResult.rows.length === 0) return;

        const currentEndDate = new Date(endDateResult.rows[0].end_date);
        const today = new Date();
        
        // Get local time in UTC+2
        const localHour = new Date(today.getTime() + (2 * 60 * 60 * 1000)).getHours();
        
        console.log('Debug - Current End Date:', currentEndDate.toISOString());
        console.log('Debug - Today:', today.toISOString());
        console.log('Debug - Current Hour (UTC):', today.getHours());
        console.log('Debug - Current Hour (Local UTC+2):', localHour);
        console.log('Debug - Date Comparison:', currentEndDate.toDateString() === today.toDateString());
        
        // Check if it's the end date and it's 13:00 or later in local time
        if (currentEndDate.toDateString() === today.toDateString() && localHour >= 13) {
            const newEndDate = new Date(currentEndDate);
            newEndDate.setDate(currentEndDate.getDate() + 14);

            console.log('Debug - New End Date:', newEndDate.toISOString());
            
            await pool.query('UPDATE end_date SET end_date = $1', [newEndDate.toISOString().split('T')[0]]);
            console.log(`End date automatically updated to ${newEndDate.toISOString().split('T')[0]}`);
        } else {
            console.log('Debug - Update conditions not met');
        }
    } catch (err) {
        console.error("Error updating end date:", err);
    }
}, 60 * 60 * 1000); // Check every hour
*/
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

// Function to clean up past bookings
const cleanupPastBookings = async () => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0); // Set to start of day

        console.log('Running cleanup for past bookings...');
        console.log('Current date:', today.toISOString());

        // Delete bookings from past dates
        const result = await pool.query(
            `DELETE FROM bookings WHERE day < $1 RETURNING *`,
            [today.toISOString().split('T')[0]]
        );

        if (result.rows.length > 0) {
            console.log(`Cleaned up ${result.rows.length} past bookings`);
        } else {
            console.log('No past bookings to clean up');
        }
    } catch (err) {
        console.error("Error cleaning up past bookings:", err);
    }
};

// Run cleanup once a day at midnight
let lastCleanupDate = null;

setInterval(() => {
    const now = new Date();
    const today = now.toISOString().split('T')[0];
    
    // If we haven't run cleanup today or it's the first run
    if (!lastCleanupDate || lastCleanupDate !== today) {
        console.log('Running cleanup for today...');
        cleanupPastBookings();
        lastCleanupDate = today;
    }
}, 24 * 60 * 60 * 1000); // Check once a day

// Run cleanup immediately when server starts
const initialCleanup = async () => {
    const now = new Date();
    const today = now.toISOString().split('T')[0];
    console.log('Running initial cleanup...');
    await cleanupPastBookings();
    lastCleanupDate = today;
};

initialCleanup();
/*
// Add end date update functionality
const updateEndDate = async () => {
    try {
        const endDateResult = await pool.query('SELECT end_date FROM end_date LIMIT 1');
        if (endDateResult.rows.length === 0) return;

        const currentEndDate = new Date(endDateResult.rows[0].end_date);
        const today = new Date();
        
        // Get local time in UTC+2
        const localHour = new Date(today.getTime() + (2 * 60 * 60 * 1000)).getHours();
        
        console.log('Debug - Current End Date:', currentEndDate.toISOString());
        console.log('Debug - Today:', today.toISOString());
        console.log('Debug - Current Hour (UTC):', today.getHours());
        console.log('Debug - Current Hour (Local UTC+2):', localHour);
        console.log('Debug - Date Comparison:', currentEndDate.toDateString() === today.toDateString());
        
        // Check if it's the end date and it's 13:00 or later in local time
        if (currentEndDate.toDateString() === today.toDateString() && localHour >= 13) {
            const newEndDate = new Date(currentEndDate);
            newEndDate.setDate(currentEndDate.getDate() + 14);

            console.log('Debug - New End Date:', newEndDate.toISOString());
            
            await pool.query('UPDATE end_date SET end_date = $1', [newEndDate.toISOString().split('T')[0]]);
            console.log(`End date automatically updated to ${newEndDate.toISOString().split('T')[0]}`);
        } else {
            console.log('Debug - Update conditions not met');
        }
    } catch (err) {
        console.error("Error updating end date:", err);
    }
};

// Run end date update check every 2 days
setInterval(() => {
    updateEndDate();
}, 2 * 24 * 60 * 60 * 1000); // Check every 2 days
*/
// Admin endpoint to set end date
app.post('/api/admin/end-date', async (req, res) => {
    console.log('Received end date update request:', {
        body: req.body,
        session: req.session,
        headers: req.headers
    });

    try {
        const { endDate } = req.body;
        
        if (!endDate) {
            return res.status(400).json({ 
                success: false,
                error: 'End date is required' 
            });
        }

        // Parse and validate the date
        const parsedDate = new Date(endDate);
        if (isNaN(parsedDate.getTime())) {
            return res.status(400).json({ 
                success: false,
                error: 'Invalid date format' 
            });
        }

        // Set the time to 13:00
        parsedDate.setHours(13, 0, 0, 0);

        // First, check if any record exists
        const checkResult = await pool.query('SELECT id FROM end_date LIMIT 1');
        
        let result;
        if (checkResult.rows.length === 0) {
            // If no record exists, insert new record
            result = await pool.query(
                'INSERT INTO end_date (end_date) VALUES ($1) RETURNING *',
                [parsedDate.toISOString()]
            );
        } else {
            // If record exists, update it
            result = await pool.query(
                'UPDATE end_date SET end_date = $1 WHERE id = $2 RETURNING *',
                [parsedDate.toISOString(), checkResult.rows[0].id]
            );
        }

        if (result.rows.length > 0) {
            res.json({ 
                success: true,
                message: 'Date de fin mise à jour avec succès', 
                endDate: result.rows[0].end_date 
            });
        } else {
            throw new Error('No rows affected');
        }
    } catch (error) {
        console.error('Error setting end date:', error);
        res.status(500).json({ 
            success: false,
            error: 'Échec de la mise à jour de la date de fin',
            details: error.message,
            debug: {
                hasSession: !!req.session,
                hasAdminId: req.session ? !!req.session.adminId : false
            }
        });
    }
});

// Add GET endpoint to retrieve current end date
app.get('/api/admin/end-date', async (req, res) => {
    try {
        const result = await pool.query('SELECT end_date FROM end_date ORDER BY id DESC LIMIT 1');
        
        if (result.rows.length > 0) {
            res.json({
                success: true,
                endDate: result.rows[0].end_date
            });
        } else {
            // If no end date exists, create one two weeks from now
            const defaultEndDate = new Date();
            defaultEndDate.setDate(defaultEndDate.getDate() + 14);
            defaultEndDate.setHours(13, 0, 0, 0);

            const insertResult = await pool.query(
                'INSERT INTO end_date (end_date) VALUES ($1) RETURNING end_date',
                [defaultEndDate.toISOString()]
            );

            res.json({
                success: true,
                endDate: insertResult.rows[0].end_date,
                isDefault: true
            });
        }
    } catch (error) {
        console.error('Error getting end date:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to get end date',
            details: error.message
        });
    }
});