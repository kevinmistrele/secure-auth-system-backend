import {Log} from "../models/Logs";

export async function addLog(action: string, user: string, details: string) {
    try {
        const log = new Log({ action, user, details });
        await log.save();
    } catch (error) {
        console.error('Erro ao salvar log:', error);
    }
}