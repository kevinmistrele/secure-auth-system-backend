import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import { authRoutes } from './routes/authRoutes'
import { connectDB } from './config/db'

dotenv.config()

connectDB()

const app = express()
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
}))
app.use(express.json())

app.use('/api', authRoutes)

app.get('/', (_req, res) => {
  res.send('API funcionando!')
})

const PORT = process.env.PORT || 3001
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`)
})
