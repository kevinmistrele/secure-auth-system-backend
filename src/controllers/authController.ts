import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { Request, Response, RequestHandler  } from 'express'
import {User} from "../models/User";

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

    const token = jwt.sign({ id: user._id, role: user.role.toLowerCase() }, process.env.JWT_SECRET!, { expiresIn: '1h' })
    res.json({ token, role: user.role.toLowerCase(), fullName: user.name, email: user.email   })
}
