import express from 'express';
import { login } from '../controllers/authenication.controller.js';
import { register } from '../controllers/authenication.controller.js';

const router = express.Router();

router.post('/login', login);
router.post('/register', register);

export default router;