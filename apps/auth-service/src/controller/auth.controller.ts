import { Request, Response, NextFunction } from "express";
import {
  checkOtpRestrictions,
  handleForgotPassword,
  sendOtp,
  trackOtpRequests,
  validateRegistrationData,
  verifyForgotPassordOtp,
  verifyOtp,
} from "../utils/auth.helper";
import prisma from "@packages/libs/prisma";
import { AuthError, ValidationError } from "@packages/error-handler";
import bcrypt from "bcryptjs";
import jwt, { JsonWebTokenError } from "jsonwebtoken";
import { setCookie } from "../utils/cookies/setCookie";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: "2026-07-29.dahlia",
});

//Register a new user
export const userRegistration = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    validateRegistrationData(req.body, "user");

    const { name, email } = req.body;

    const existingUser = await prisma.users.findUnique({ where: { email } });

    if (existingUser) {
      return next(new ValidationError("User already exists with this email"));
    }

    await checkOtpRestrictions(email);
    await trackOtpRequests(email);
    await sendOtp(name, email, "user-activation-mail");

    res.status(200).json({
      message: "OTP sent to email. Please email verify your account.",
    });
  } catch (error) {
    return next(error);
  }
};

//verify user using OTP
export const verifyUser = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const { email, otp, password, name } = req.body;
    if (!email || !otp || !password || !name) {
      return next(new ValidationError("All fields are required"));
    }

    const existingUser = await prisma.users.findUnique({ where: { email } });

    if (existingUser) {
      return next(
        new ValidationError("User already existing with this email!!"),
      );
    }

    await verifyOtp(email, otp, next);

    const hashedPassword = await bcrypt.hash(password, 10);

    await prisma.users.create({
      data: { name, email, password: hashedPassword },
    });

    res.status(201).json({
      success: true,
      message: "User registered successfully!!",
    });
  } catch (error) {
    return next(error);
  }
};

//login user
export const loginUser = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return next(new ValidationError("Email and Password are required"));
    }

    const user = await prisma.users.findUnique({ where: { email } });

    if (!user) {
      return next(new AuthError("User does not exist"));
    }

    //verify password
    const isMatch = await bcrypt.compare(password, user.password!);

    if (!isMatch) {
      return next(new AuthError("Invalid email or password"));
    }

    //Generate access and refresh token
    const accessToken = jwt.sign(
      { id: user.id, role: "user" },
      process.env.JWT_SECRET as string,
      {
        expiresIn: "15m",
      },
    );

    const refreshToken = jwt.sign(
      { id: user.id, role: "user" },
      process.env.REFRESH_TOKEN_SECRET as string,
      {
        expiresIn: "7d",
      },
    );

    //store the refresh and access token in an httpOnly secure cookie
    setCookie(res, "refresh_token", refreshToken);
    setCookie(res, "access_token", accessToken);

    res.status(200).json({
      message: "login successfully",
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    return next(error);
  }
};

export const getUser = async (req: any, res: Response, next: NextFunction) => {
  try {
    const user = req.user;

    res.status(201).json({
      success: true,
      user,
    });
  } catch (error) {
    next(error);
  }
};

// User Forgot password
export const userForgotPassword = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  await handleForgotPassword(req, res, next, "user");
};

//verify forgot password otp
export const verifyUserForgotPassword = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  await verifyForgotPassordOtp(req, res, next);
};

// Reset User password
export const resetUserPassword = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return next(new ValidationError("Email and new password are required!"));
    }

    const user = await prisma.users.findUnique({ where: { email } });

    if (!user) return next(new ValidationError(" user not found"));

    //compare new password with the existing one
    const isSamePassword = await bcrypt.compare(newPassword, user.password!);

    if (isSamePassword) {
      return next(
        new ValidationError(
          "New password cannot be same as the current password",
        ),
      );
    }

    //hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.users.update({
      where: { email },
      data: { password: hashedPassword },
    });

    res.status(200).json({
      message: "Password reset successfully",
    });
  } catch (error) {
    next(error);
  }
};

//refresh token user
export const refreshToken = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const refreshToken = req.cookies.refresh_token;

    if (!refreshToken) {
      throw new ValidationError("Unauthorized! No refresh token.");
    }

    const decoded = jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET as string,
    ) as { id: string; role: string };

    if (!decoded || !decoded.id || !decoded.role) {
      return new JsonWebTokenError("Forbidden, Invalid refresh token.");
    }

    // let account;

    // if(decoded.role === 'user')
    const user = await prisma.users.findUnique({ where: { id: decoded.id } });

    if (!user) {
      return new AuthError("Forbidden! User/Seller not found");
    }

    const newAccessToken = jwt.sign(
      { id: decoded.id, role: decoded.role },
      process.env.JWT_SECRET as string,
      { expiresIn: "15m" },
    );

    setCookie(res, "access_token", newAccessToken);

    return res.status(201).json({ success: true });
  } catch (error) {
    return next(error);
  }
};

// Register a new Seller
export const registerSeller = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    validateRegistrationData(req.body, "seller");
    const { name, email } = req.body;

    const exisitingSeller = await prisma.sellers.findUnique({
      where: { email },
    });

    if (exisitingSeller) {
      throw new ValidationError("Seller already exists with this email!");
    }

    await checkOtpRestrictions(email);
    await trackOtpRequests(email);
    await sendOtp(name, email, "seller-activation");

    res
      .status(200)
      .json({ message: "OTP sent to email. Please verify your account." });
  } catch (error) {
    next(error);
  }
};

//verify Seller with OTP
export const verifySeller = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const { email, otp, password, name, phone_number, country } = req.body;

    if (!email || !otp || !password || !name || !phone_number || !country) {
      return next(new ValidationError("All fields are required!"));
    }

    const exisitingSeller = await prisma.sellers.findUnique({
      where: { email },
    });

    if (exisitingSeller) {
      return next(
        new ValidationError("Seller Already exists with this email!"),
      );
    }
    await verifyOtp(email, otp, next);

    const hashedPassword = await bcrypt.hash(password, 10);

    const seller = await prisma.sellers.create({
      data: {
        name,
        email,
        password: hashedPassword,
        country,
        phone_number,
      },
    });

    res
      .status(201)
      .json({ seller, message: "Seller registered successfully!" });
  } catch (error) {
    next(error);
  }
};

//Create a new Shop
export const createShop = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const { name, bio, address, opening_hours, website, category, sellerId } =
      req.body;

    if (
      !name ||
      !bio ||
      !address ||
      !opening_hours ||
      !website ||
      !category ||
      !sellerId
    ) {
      return next(new ValidationError("All fields are required!"));
    }

    const shopData: any = {
      name,
      bio,
      address,
      opening_hours,
      website,
      category,
      sellerId,
    };

    if (website && website.trim() === "") {
      shopData.website = website;
    }

    const shop = await prisma.shops.create({
      data: shopData,
    });

    res.status(201).json({
      success: true,
      shop,
    });
  } catch (error) {
    next(error);
  }
};

//create stripe connect account link
export const createStripeConnectLink = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const { sellerId } = req.body;

    if (!sellerId) return next(new ValidationError("Seller ID is required"));

    const seller = await prisma.sellers.findUnique({
      where: {
        id: sellerId,
      },
    });

    if (!seller)
      return next(new ValidationError("Seller is not available with this id!"));

    // const account = await stripe.accounts.create({
    //   type: "express",
    //   email: seller?.email,
    //   country: "US",
    //   capabilities: {
    //     card_payments: { requested: true },
    //     transfers: { requested: true },
    //   },
    // });

    const account = await stripe.v2.core.accounts.create({
  contact_email: seller.email,
  dashboard: "express",

  defaults: {
  responsibilities: {
    fees_collector: "application",
    losses_collector: "application",
  },
},

  identity: {
    country: "us",
    entity_type: "individual",
  },

  configuration: {
    merchant: {
      capabilities: {
        card_payments: {
          requested: true,
        },
      },
    },

    recipient: {
      capabilities: {
        stripe_balance: {
          stripe_transfers: {
            requested: true,
          },
        },
      },
    },
  },
});

    await prisma.sellers.update({
      where: {
        id: sellerId,
      },
      data: {
        stripeId: account.id,
      },
    });

    const accountLink = await stripe.accountLinks.create({
      account: account.id,
      refresh_url: `http://localhost:3000/success`,
      return_url: `http://localhost:3000/success`,
      type: "account_onboarding",
    });

    res.json({ url: accountLink.url });
  } catch (error) {
    return next(error);
  }
};

//login Seller
export const loginSeller = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return next(new ValidationError("Email and password are required"));

    const seller = await prisma.sellers.findUnique({ where: { email } });
    if (!seller) return next(new ValidationError("Invalid email or password!"));

    // Verify Password
    const isMatch = await bcrypt.compare(password, seller.password!);
    if (!isMatch)
      return next(new ValidationError("Invalid email or password!"));

    //Generate access and refresh tokens
    const accessToken = jwt.sign(
      { id: seller.id, role: "seller" },
      process.env.JWT_SECRET as string,
      { expiresIn: "15m" },
    );

    const refreshToken = jwt.sign(
      { id: seller.id, role: "seller" },
      process.env.REFRESH_TOKEN_SECRET as string,
      { expiresIn: "7d" },
    );

    // store refresh token and access token
    setCookie(res, "seller-refresh-token", refreshToken);
    setCookie(res, "seller-access-token", accessToken);
  } catch (error) {
    next(error);
  }
};

//get logged in seller
export const getSeller = async (
  req: any,
  res: Response,
  next: NextFunction,
) => {
  try {
    const seller = req.seller;
    res.status(201).json({
      success: true,
      seller,
    });
  } catch (error) {
    next(error);
  }
};
