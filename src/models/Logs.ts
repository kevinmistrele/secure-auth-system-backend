import { Schema, model } from 'mongoose';

const logSchema = new Schema({
    action: { type: String, required: true },
    user: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    details: { type: String, required: true },
});

export const Log = model('Log', logSchema);