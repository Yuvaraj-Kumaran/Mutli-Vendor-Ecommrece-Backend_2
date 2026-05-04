import { Request, Response, NextFunction } from "express";
import { checkOtpRestrictions, handleForgotPassword, sendOtp, trackOtpRequests, validateRegistrationData, verifyForgotPassordOtp, verifyOtp } from "../utils/auth.helper";
import prisma from "@packages/libs/prisma";
import { AuthError, ValidationError } from "@packages/error-handler";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { setCookie } from "../utils/cookies/setCookie";


//Register a new user
export const userRegistration = async (req: Request, res: Response, next: NextFunction) => {
    
    try {
        validateRegistrationData(req.body, "user");

    const {name, email} = req.body;

    const existingUser = await prisma.users.findUnique({where: {email}});

    if(existingUser){
        return next(new ValidationError("User already exists with this email"))
    };

    await checkOtpRestrictions(email, next);
    await trackOtpRequests(email, next);
    await sendOtp(name, email, "user-activation-mail");

    res.status(200).json({
        message: "OTP sent to email. Please email verify your account."
    });
    } catch (error) {
        return next(error);
    }
}

//verify user using OTP
export const verifyUser = async(req: Request, res: Response, next: NextFunction) => {
    try {
        const {email, otp, password, name} = req.body;
        if(!email || !otp || !password ||!name){
            return next(new ValidationError("All fields are required"));
        };

        const existingUser = await prisma.users.findUnique({where: {email}});

        if(existingUser){
            return next(new ValidationError("User already existing with this email!!"));
        }

        await verifyOtp(email, otp , next);

        const hashedPassword = await bcrypt.hash(password, 10);

        await prisma.users.create({
            data: {name, email, password: hashedPassword},
        });

        res.status(201).json({
            success: true,
            message: "User registered successfully!!"
        });

    } catch (error) {
        return next(error);
    }
}

//login user
export const loginUser = async(req: Request, res: Response, next: NextFunction) => {
    try {
        const {email, password} = req.body;

        if(!email || !password){
            return next(new ValidationError("Email and Password are required"));
        }

        const user = await prisma.users.findUnique({where: {email}});

        if(!user){
            return next(new AuthError("User does not exist"));
        }

        //verify password
        const isMatch = await bcrypt.compare(password, user.password!);

        if(!isMatch){
            return next(new AuthError("Invalid email or password"));
        }

        //Generate access and refresh token
        const accessToken = jwt.sign({id: user.id, role: "user"},
            process.env.JWT_SECRET as string,
            {
                expiresIn: "15m"
            }
        );

        const refreshToken = jwt.sign({id: user.id, role: "user"},
            process.env.REFRESH_TOKEN_SECRET as string,
            {
                expiresIn: "7d",
            }
        );

        //store the refresh and access token in an httpOnly secure cookie
        setCookie (res, "refresh_token", refreshToken);
        setCookie (res, "access_token", accessToken);

        res.status(200). json({
            message: "login successfully",
            user: {
                id: user.id,
                email: user.email,
                name: user.name
            }
        })

    } catch (error) {
        return next(error);
    }
} 

// User Forgot password
export const userForgotPassword = async(req: Request, res: Response, next: NextFunction) => {
    await handleForgotPassword (req, res, next, "user");
}

//verify forgot password otp
export const verifyUserForgotPassword = async( req: Request, res: Response, next: NextFunction) => {
    await verifyForgotPassordOtp(req, res, next);
}

// Reset User password
export const resetUserPassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const {email, newPassword} = req.body;

        if(!email || !newPassword){
            return next(new ValidationError("Email and new password are required!"));
        }

        const user = await prisma.users.findUnique({where:{email}});

        if(!user) return next(new ValidationError(" user not found"));

        //compare new password with the existing one
        const isSamePassword = await bcrypt.compare(newPassword, user.password!);

        if(isSamePassword){
            return next(new ValidationError("New password cannot be same as the current password"));
        }

        //hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await prisma.users.update({
            where: {email},
            data: {password: hashedPassword},
        })

        res.status(200).json({
            message: "Password reset successfully"
        })

    } catch (error) {
        next(error);
    }
}