export class AppError extends Error {
    public readonly statusCode: number;
    public readonly isOperational?: boolean;
    public readonly details: any;

    constructor(message: string, statusCode: number, isOperationl?: true, details?: any){
        super(message);
        this.statusCode = statusCode;
        this.isOperational = isOperationl;
        this.details = details;
        Error.captureStackTrace(this);
    }
}

//Not found error
export class NotFounder extends AppError{
    constructor (message = "Data Not Found"){
        super(message, 404, true);
    }
}

//validation Error (use for joi/zod/react-hook-form validation errors)
export class ValidationError extends AppError{
    constructor(message = "Invalid request data", details?: any){
        super(message, 400, true, details)
    }
}

// Authentication error
export class AuthError extends AppError{
    constructor(message = "Unauthorised"){
        super(message, 401);
    }
}

// ForbiddenError (For insufficent permission)
export class ForbiddenError extends AppError{
    constructor (message = "Forbidden"){
        super (message, 403)
    }
}

// Database Error (For MongoDB/ Postgres Errors)
export class DatabaseError extends AppError{
    constructor (message = "Database Error", details?: any){
        super (message, 500, true, details)
    }
}

// Rate Limit Error (If user exceeds API limits)
export class Ratelimitor extends AppError{
    constructor( message = "Too many request, please try again later"){
        super( message, 429);
    }
}

export { errorMiddleware } from './error-middleware';