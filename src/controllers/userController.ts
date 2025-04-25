import { Request, Response } from "express";
import { User } from "../models/User";

export const getUsers = async (req: Request, res: Response) => {
    try {
        const users = await User.find(); // Busca todos os usuários no banco
        res.json(users); // Retorna os usuários encontrados
    } catch (err) {
        res.status(500).json({ error: "Erro ao buscar usuários" });
    }
};
