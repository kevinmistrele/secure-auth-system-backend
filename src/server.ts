import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import { authRoutes } from './routes/authRoutes'
import { connectDB } from './config/db'

dotenv.config()

connectDB()

const app = express()
app.use(cors())
app.use(express.json())

app.use('/api', authRoutes)

app.get('/', (_req, res) => {
  res.send('API funcionando!')
})

app.listen(3001, () => {
  console.log('Servidor rodando na porta 3001')
})
