import { Request, Response } from 'express';
import {Log} from "../models/Logs";


export const getLogs = async (req: Request, res: Response) => {
    try {
        const logs = await Log.find().sort({ timestamp: -1 }).limit(100);
        res.json(logs);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar logs' });
    }
};