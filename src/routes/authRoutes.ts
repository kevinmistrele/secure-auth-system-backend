import { Router } from 'express'
import {
    registerUser,
    loginUser,
    registerAdmin,
    updateUser,
    deleteUser,
    requestPasswordReset, resetPassword
} from '../controllers/authController'
import { verifyToken, isAdmin } from '../middlewares/authMiddleware'
import {getUsers} from "../controllers/userController";

const router = Router()

router.post('/register', registerUser)
router.post('/register-admin', verifyToken, isAdmin, registerAdmin)
router.post('/login', loginUser)
router.post('/request-password-reset', requestPasswordReset);
router.post('/reset-password', resetPassword);

router.get("/users", verifyToken, isAdmin, getUsers);

router.put('/users/:id', verifyToken, updateUser);

router.delete('/users/:id', deleteUser);

export const authRoutes = router
