import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

export const verifyToken = (
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
        res.status(401).json({ error: "Token não fornecido" });
        return;
    }

    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET!) as any;
        next();
    } catch {
        res.status(401).json({ error: "Token inválido" });
    }
};

export const isAdmin = (
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    if (req.user?.role !== "admin") {
        res.status(403).json({ error: "Apenas administradores podem realizar esta ação" });
        return;
    }
    next();
};
