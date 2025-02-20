// email.js
import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

const transporter = nodemailer.createTransport({
    service: "outlook", // Use your email service (e.g., Gmail, SendGrid)
    auth: {
        user: process.env.EMAIL_USER, // Your email address from environment variable
        pass: process.env.EMAIL_PASS, // Your email password from environment variable
    },
});

export const sendEmail = async (to, subject, text) => {
    try {
        const mailOptions = {
            from: process.env.EMAIL_USER, // Sender email
            to, // Recipient email
            subject, // Email subject
            text, // Email body
        };

        await transporter.sendMail(mailOptions);
        console.log(`Email sent to ${to}`);
    } catch (error) {
        console.error("Error sending email:", error);
    }
};