import nodemailer from 'nodemailer';

export const sendResetPasswordEmail = async (email: string, resetLink: string): Promise<boolean> => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset',
        text: `Click the following link to reset your password: ${resetLink}`
    };

    try {
        await transporter.sendMail(mailOptions);
        return true; // Retorna true se o e-mail for enviado com sucesso
    } catch (error) {
        console.error('Error sending email:', error);
        return false; // Retorna false em caso de erro
    }
};
