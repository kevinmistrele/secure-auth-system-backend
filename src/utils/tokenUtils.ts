import jwt from 'jsonwebtoken';

export const generateResetToken = (userId: string) => {
    const token = jwt.sign({ userId }, process.env.JWT_SECRET!, { expiresIn: '15m' });
    return token;
};

export const verifyResetToken = (token: string) => {
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { userId: string };
        return decoded.userId;
    } catch (error) {
        return null;
    }
};
