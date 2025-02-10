// email.js
import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
    service: "gmail", // Use your email service (e.g., Gmail, SendGrid)
    auth: {
        user: "your-email@gmail.com", // Your email address
        pass: "your-email-password", // Your email password or app-specific password
    },
});

export const sendEmail = async (to, subject, text) => {
    try {
        const mailOptions = {
            from: "your-email@gmail.com", // Sender email
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