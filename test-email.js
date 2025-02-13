// test-email.js
import { sendEmail } from './email.js';

const testSendEmail = async () => {
    const to = 'knnwouters@gmail.com';
    const subject = 'Test Email';
    const text = 'This is a test email.';

    try {
        await sendEmail(to, subject, text);
        console.log('Test email sent successfully');
    } catch (error) {
        console.error('Error sending test email:', error);
    }
};

testSendEmail();