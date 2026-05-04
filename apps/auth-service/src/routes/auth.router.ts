import express, { Router } from "express";
import { loginUser, resetUserPassword, userForgotPassword, userRegistration, verifyUser } from "../controller/auth.controller";
import { verifyForgotPassordOtp } from "../utils/auth.helper";

const router: Router = express.Router();

router.post("/user-registration", userRegistration);

router.post("/verify-user", verifyUser);

router.post("/login-user", loginUser)

router.post("/forgot-password-user", userForgotPassword);

router.post("/reset-password-user", resetUserPassword);

router.post("/verify-forgot-passord-user", verifyForgotPassordOtp);


export default router;