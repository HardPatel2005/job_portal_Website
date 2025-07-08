// backend/middlewares/isAuthenticated.js
import jwt from "jsonwebtoken";

const isAuthenticated = async (req, res, next) => {
    try {
        const token = req.cookies.token;
        if (!token) {
            // Log when a request comes without a token
            console.log(`[AUTH-DEBUG] Unauthenticated: No token provided for ${req.method} ${req.originalUrl} from IP: ${req.ip}`);
            return res.status(401).json({
                message: "User not authenticated",
                success: false,
            });
        }

        let decodedPayload;
        try {
            // Verify the token and decode its payload
            decodedPayload = await jwt.verify(token, process.env.SECRET_KEY);
        } catch (jwtError) {
            // Catch specific JWT errors (e.g., token expired, invalid signature)
            if (jwtError.name === 'TokenExpiredError') {
                console.log(`[AUTH-DEBUG] Token Expired: for ${req.method} ${req.originalUrl} from IP: ${req.ip}`);
                return res.status(401).json({
                    message: "Token expired, please log in again.",
                    success: false
                });
            } else if (jwtError.name === 'JsonWebTokenError') {
                console.log(`[AUTH-DEBUG] Invalid Token: ${jwtError.message} for ${req.method} ${req.originalUrl} from IP: ${req.ip}`);
                return res.status(401).json({
                    message: "Invalid token.",
                    success: false
                });
            } else {
                // Unexpected JWT verification error
                console.error(`[AUTH-DEBUG] JWT Verification Error: ${jwtError.message} for ${req.method} ${req.originalUrl} from IP: ${req.ip}`);
                return res.status(500).json({
                    message: "Authentication failed due to token error.",
                    success: false
                });
            }
        }

        // Check if decode has the userId property (assuming your token payload contains 'userId')
        if (!decodedPayload || !decodedPayload.userId) {
            console.log(`[AUTH-DEBUG] Token missing userId: for ${req.method} ${req.originalUrl} from IP: ${req.ip}. Payload: ${JSON.stringify(decodedPayload)}`);
            return res.status(401).json({
                message: "Invalid token payload (missing user ID).",
                success: false
            });
        }

        req.id = decodedPayload.userId; // Assign the userId to req.id
        // Log successful authentication with the user ID and IP
        console.log(`[AUTH-DEBUG] Authenticated: User ID ${req.id} for ${req.method} ${req.originalUrl} from IP: ${req.ip}`);

        next(); // Proceed to the next middleware or route handler

    } catch (unexpectedError) {
        // Catch any other unexpected errors during the middleware execution
        console.error(`[AUTH-DEBUG] Unexpected Error in isAuthenticated middleware: ${unexpectedError.message} for ${req.method} ${req.originalUrl} from IP: ${req.ip}`);
        return res.status(500).json({
            message: "Internal server error during authentication.",
            success: false
        });
    }
};

export default isAuthenticated;