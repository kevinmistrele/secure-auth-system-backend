import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { Request, Response, RequestHandler  } from 'express'
import {User} from "../models/User";
import {generateResetToken, verifyResetToken} from "../utils/tokenUtils";
import {sendResetPasswordEmail} from "../services/emailService";

const users: { id: number, name: string, email: string, password: string, role: string }[] = []

export const registerUser = async (req: Request, res: Response): Promise<void> => {
    const { name, email, password } = req.body
    const existing = await User.findOne({ email })
    if (existing) {
        res.status(400).json({ error: 'Email já cadastrado' })
        return
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    const user = new User({ name, email, password: hashedPassword })
    await user.save()

    res.status(201).json({ message: 'Usuário registrado com sucesso' })
}

export const registerAdmin = async (req: Request, res: Response): Promise<void> => {
    const { name, email, password } = req.body
    const existing = await User.findOne({ email })
    if (existing) {
        res.status(400).json({ error: 'Email já cadastrado' })
        return
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    const user = new User({ name, email, password: hashedPassword, role: 'admin' })
    await user.save()

    res.status(201).json({ message: 'Administrador registrado com sucesso' })
}

export const loginUser = async (req: Request, res: Response): Promise<void> => {
    const { email, password } = req.body
    const user = await User.findOne({ email })
    if (!user) {
        res.status(404).json({ error: 'Usuário não encontrado' })
        return
    }

    const match = await bcrypt.compare(password, user.password)
    if (!match) {
        res.status(401).json({ error: 'Senha incorreta' })
        return
    }

    const token = jwt.sign({ id: user.id, role: user.role.toLowerCase() }, process.env.JWT_SECRET!, { expiresIn: '1h' })
    res.json({ token, role: user.role.toLowerCase(), fullName: user.name, email: user.email, id: user.id })
}

export const updateUser = async (req: Request, res: Response): Promise<void> => {
    const { id } = req.params; // Recebe o id do usuário a ser atualizado
    const { fullName, role } = req.body; // Recebe o novo nome e, opcionalmente, o novo role

    try {
        // Verifica se o usuário existe
        const user = await User.findById(id);
        if (!user) {
            res.status(404).json({ error: 'Usuário não encontrado' });
            return;
        }

        // Atualiza o nome
        if (fullName) {
            user.name = fullName;
        }

        // Atualiza o role somente se fornecido
        if (role) {
            if (role !== "user" && role !== "admin") {
                res.status(400).json({ error: 'Role inválido. Apenas "user" ou "admin" são permitidos.' });
                return;
            }
            user.role = role;
        }

        await user.save(); // Salva as atualizações no banco de dados

        res.status(200).json({
            message: 'Usuário atualizado com sucesso',
            user: { id: user.id, fullName: user.name, email: user.email, role: user.role }
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar o usuário' });
    }
};

export const deleteUser = async (req: Request, res: Response): Promise<void> => {
    const { id } = req.params; // Recebe o id do usuário a ser deletado

    try {
        // Verifica se o usuário existe e deleta
        const user = await User.findByIdAndDelete(id);

        if (!user) {
            res.status(404).json({ error: 'Usuário não encontrado' });
            return;
        }

        res.status(200).json({ message: 'Usuário excluído com sucesso' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao excluir o usuário' });
    }
};

export const requestPasswordReset = async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            res.status(404).json({ success: false, error: 'E-mail não encontrado.' });
            return;
        }

        const token = generateResetToken(user.id);
        const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

        const emailSent = await sendResetPasswordEmail(email, resetLink);

        if (emailSent) {
            res.status(200).json({ success: true, message: 'Link de redefinição enviado para seu e-mail!' });
        } else {
            res.status(500).json({ success: false, error: 'Erro ao enviar o e-mail.' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Erro ao processar a solicitação.' });
    }
};

export const resetPassword = async (req: Request, res: Response): Promise<void> => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        res.status(400).json({ success: false, error: 'Token e nova senha são obrigatórios.' });
        return;
    }

    try {
        const userId = verifyResetToken(token);
        if (!userId) {
            res.status(400).json({ success: false, error: 'Token inválido ou expirado.' });
            return;
        }

        const user = await User.findById(userId);
        if (!user) {
            res.status(404).json({ success: false, error: 'Usuário não encontrado.' });
            return;
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();

        res.status(200).json({ success: true, message: 'Senha atualizada com sucesso.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Erro ao processar a redefinição de senha.' });
    }
};


