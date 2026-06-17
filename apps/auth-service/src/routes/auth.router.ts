import express, { Router } from "express";
import { getUser, loginUser, refreshToken, resetUserPassword, userForgotPassword, userRegistration, verifyUser, verifyUserForgotPassword } from "../controller/auth.controller";
import isAuthenticated from "@packages/middleware/isAuthenticated";



const router: Router = express.Router();

router.post("/user-registration", userRegistration);

router.post("/verify-user", verifyUser);

router.post("/login-user", loginUser)

router.post("/forgot-password-user", userForgotPassword);

router.post("/reset-password-user", resetUserPassword);

router.post("/verify-forgot-password-user", verifyUserForgotPassword);

router.post("/refresh-token", refreshToken);

router.get("/logged-token-user", isAuthenticated, getUser);


export default router;