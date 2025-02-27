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
// import { Pool } from 'pg';

import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = 3001;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(
    session({
        secret: process.env.SECRET_KEY, // Replace with a strong secret key
        resave: false,
        saveUninitialized: true,
        cookie: {
            secure: false, // Set to true if using HTTPS
            httpOnly: true, // Prevent client-side JavaScript from accessing the cookie
            maxAge: 1000 * 60 * 60 * 24, // Session expiration time (e.g., 1 day)
        },
    })
);

// Middleware to check if an admin is authenticated
const isAdminAuthenticated = (req, res, next) => {
    if (req.session.adminId) {
        next();
    } else {
        res.status(403).json({ error: "Unauthorized access" });
    }
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
        CREATE TABLE IF NOT EXISTS availability_settings
            (
                day          DATE PRIMARY KEY,
                is_open      BOOLEAN   DEFAULT true,
                max_bookings INTEGER   DEFAULT 10,
                created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

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

// Example: Call this function when a booking is canceled
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



app.post("/admin/login", async (req, res) => {
    const { firstName, password } = req.body;
    try {
        // Fetch the admin from the database
        const adminQuery = await pool.query(
            `SELECT * FROM admins WHERE first_name = $1`,
            [firstName]
        );

        if (adminQuery.rows.length === 0) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const admin = adminQuery.rows[0];

        // Compare the provided password with the hashed password
        const isPasswordValid = await bcrypt.compare(password, admin.password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // Store the admin's ID in the session
        req.session.adminId = admin.id;

        // Delete previous bookings
        const today = new Date().toISOString().split("T")[0];
        try {
            await pool.query(`DELETE FROM bookings WHERE day < $1`, [today]);
        } catch (deleteError) {
            console.error("Error deleting previous bookings:", deleteError);
            return res.status(500).json({ error: "Error deleting previous bookings" });
        }

        // Return the admin ID in the response
        res.json({ adminId: admin.id, message: "Login successful" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Apply the isAdminAuthenticated middleware to all /admin routes
app.use("/admin", isAdminAuthenticated);

// Admin dashboard route (requires authentication)
app.get("/admin/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin-dashboard.html"));
});

// Admin logout route (requires authentication)
app.get("/admin/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
            return res.status(500).json({ error: "Could not log out" });
        }

        // Clear the session cookie
        res.clearCookie("connect.sid"); // "connect.sid" is the default session cookie name
        res.redirect("/admin"); // Redirect to the login page
    });
});

// Admin bookings API route (requires authentication)
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

// Admin endpoint to update availability
// Update this endpoint in your server code
// app.put("/api/admin/availability/:day", isAdminAuthenticated, async (req, res) => {
//     const { day } = req.params;
//     const { isOpen, maxBookings } = req.body;
//
//     try {
//         await pool.query(
//             `INSERT INTO availability_settings (day, is_open, max_bookings)
//              VALUES ($1, $2, $3)
//              ON CONFLICT (day)
//                  DO UPDATE SET
//                                is_open = $2,
//                                max_bookings = $3,
//                                updated_at = CURRENT_TIMESTAMP`,
//             [day, isOpen, maxBookings]
//         );
//
//         res.json({ success: true });
//     } catch (err) {
//         res.status(500).json({ error: err.message });
//     }
// });

// Modified availability check endpoint
// app.get("/api/availability/:day", async (req, res) => {
//     const { day } = req.params;
//
//     try {
//         // First check if the day is open
//         const settingsQuery = await pool.query(
//             `SELECT is_open, max_bookings
//              FROM availability_settings
//              WHERE day = $1`,
//             [day]
//         );
//
//         // If no settings found, use defaults
//         const settings = settingsQuery.rows[0] || {
//             is_open: true,
//             max_bookings: 10
//         };
//
//         if (!settings.is_open) {
//             return res.json({ isFullyBooked: true, isClosed: true });
//         }
//
//         // Check current booking count
//         const countQuery = await pool.query(
//             `SELECT COUNT(*) as count
//              FROM bookings
//              WHERE day = $1`,
//             [day]
//         );
//
//         const isFullyBooked = countQuery.rows[0].count >= settings.max_bookings;
//
//         res.json({
//             isFullyBooked,
//             isClosed: false,
//             currentBookings: countQuery.rows[0].count,
//             maxBookings: settings.max_bookings
//         });
//
//     } catch (err) {
//         res.status(500).json({ error: err.message });
//     }
// });

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



// Start the server
const PORT = process.env.PORT || 5432;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});




// const password = "admin123"; // Replace with the desired password
// const saltRounds = 10;
// const hash = await bcrypt.hash(password, saltRounds);
// console.log(hash); // Use this hash in the INSERT query