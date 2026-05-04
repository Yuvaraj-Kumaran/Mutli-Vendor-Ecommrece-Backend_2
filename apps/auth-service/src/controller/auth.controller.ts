import { Request, Response, NextFunction } from "express";
import { checkOtpRestrictions, sendOtp, trackOtpRequests, validateRegistrationData, verifyOtp } from "../utils/auth.helper";
import prisma from "@packages/libs/prisma";
import { ValidationError } from "@packages/error-handler";
import bcrypt from "bcryptjs";


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