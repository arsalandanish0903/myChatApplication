import { asyncHandler } from "../utilities/asyncHandler.utility.js";
import { errorHandler } from "../utilities/errorHandler.utility.js";
import jwt from 'jsonwebtoken'

export const isAuthenticated = asyncHandler(async (req, res, next) => {
    console.log("Cookies:", req.cookies);
    console.log("Authorization Header:", req.headers['authorization']);

    const token = req.cookies.token || req.headers['authorization']?.replace("Bearer ", "");
    console.log("Extracted Token:", token); // Debugging line

    if (!token) {
        return next(new errorHandler("Invalid token", 400));
    }

    try {
        const tokenData = jwt.verify(token, process.env.JWT_SECRET);
        console.log("Decoded Token Data:", tokenData); // Debugging line
        req.user = tokenData;
        next();
    } catch (error) {
        console.error("JWT Verification Error:", error);
        return next(new errorHandler("Invalid token", 400));
    }
});
