import { Router } from 'express'
import { registerUser, loginUser, registerAdmin } from '../controllers/authController'
import { verifyToken, isAdmin } from '../middlewares/authMiddleware'
import {getUsers} from "../controllers/userController";

const router = Router()

router.post('/register', registerUser)
router.post('/register-admin', verifyToken, isAdmin, registerAdmin)
router.post('/login', loginUser)

router.get("/users", verifyToken, isAdmin, getUsers);

export const authRoutes = router
