import crypto from "crypto";
import { ValidationError } from "@packages/error-handler";
import { NextFunction, Request, Response } from "express";
import {redis} from "@packages/libs/redis";
import { sendEmail } from "./sendMail";
import prisma from "@packages/libs/prisma";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const validateRegistrationData = (data: any, userType: "user" | "seller") => {
    const {name, email, password, phone_number, country} = data;

    if((!name || !email || !password || (userType === "seller" && (!phone_number || !country)))){
        throw new ValidationError(`Missing Required Fields!`)
    }

    if(!emailRegex.test(email)){
        throw new ValidationError("Invalid email format");
    }


}

export const checkOtpRestrictions = async (email:string, next: NextFunction) => {
    if (await redis.get(`otp_lock:${email}`)){
        return next(new ValidationError("Account locked due to multiple failed attempts! Try again after 30 minutes"));
    }
    if(await redis.get(`otp_spam_lock:${email}`)){
        return next(new ValidationError("Too many OTP requests. Please wait an hour before sending request again."))
    }
    if(await redis.get(`otp_cooldown:${email}`)){
        return next(new ValidationError("Please wait one minute before requesting a new OTP."))
    }
};

export const trackOtpRequests = async (email: string, next: NextFunction) => {
    const otpRequestKey = `otp_request_count:${email}`;
    const otpRequests = parseInt((await (redis.get(otpRequestKey))) || "0");

    if(otpRequests >= 2 ){
        await redis.set(`otp_spam_lock:${email}`, "locked", "EX", 3600); // Lock for an hour
        return next(new ValidationError("Too Many OTP requests. Please wait an hour before requesting again!"));
    };

    await redis.set(otpRequestKey, otpRequests + 1, "EX", 3600 );
}

export const sendOtp = async (name: string, email: string, template: string) => {
    const otp = crypto.randomInt(1000, 9999).toString();

    await sendEmail(email, "Verify your email", template, {name, otp});
    
    await redis.set(`otp:${email}`,otp, "EX", 300);

    await redis.set(`otp_cooldown:${email}`, "true", "EX", 60);
}

export const verifyOtp = async( email: string, otp: string, next: NextFunction) =>{
    const storedOtp = await redis.get(`otp:${email}`);

    if(!storedOtp){
        throw new ValidationError("Invalid or expired OTP");
    }

    const failedAttemptsKey = `otp_attempts:${email}`;

    const failedAttempts = parseInt((await redis.get(failedAttemptsKey)) || "0");

    if (storedOtp !== otp){
        if(failedAttempts >= 2){
            await redis.set(`otp_lock:${email}`, "locked", "EX", 1800); //lock for 30 minutes
            await redis.del(`otp:${email}`, failedAttemptsKey);

            throw new ValidationError("Too many failed attempts. Please try agian after 30 minutes");
        }

        await redis.set(failedAttemptsKey, failedAttempts+1, "EX", 300);

        throw new ValidationError(`Incorrectn OTP. ${2 - failedAttempts} attempts left.`);
    };

    await redis.del(`otp:${email}`, failedAttemptsKey);
};

export const handleForgotPassword = async (req: Request, res: Response, next: NextFunction, userType: "user" | "seller") => {

    try {
        const {email} = req.body;

        if(!email) throw new ValidationError("Email is required");

        //Find user/seller
        const user = userType === "user" && await prisma.users.findUnique({where: {email}});

        if(!user) throw new ValidationError(`${userType} not found`);

        //check otp restrictions
        await checkOtpRestrictions(email, next);
        await trackOtpRequests(email, next);

        //Generate OTP
        await sendOtp(email, user.name, "forgot-password-user-mail");

        res.status(200).json({
            message: "OTP sent to your email. Please verify your account"
        })
    } catch (error) {
        
    }
}

export const verifyForgotPassordOtp = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const {email, otp} = req.body;
        
        if(!email || !otp)
            throw new ValidationError("Email and OTP are required");

        await verifyOtp(email, otp, next);

        res.status(200).json({
            message: "OTP verified, you can reset your passowrd"
        })
    } catch (error) {
        next(error);
    }
}