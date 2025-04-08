import axios from "axios";

// Client-side model (no database ID)
export interface LoginRequest {
    username: string;
    password: string;
}

export interface RegisterRequest {
    username: string;
    password: string;
    email: string;
}

// Server-side model (includes database ID)
export interface User {
    id: number;
    username: string;
    email: string;
}

export interface LoginResponse {
    message: string;
    mfa_required?: "otp";
}

export interface AuthResponse {
    message: string;
    user?: {
        id: number;
        username: string;
        email: string;
    };
}

export interface OtpVerifyRequest {
    otp_token: string;
}

export interface OtpVerifyResponse {
    message: string;
}

export interface LogoutResponse {
    message: string;
}

export interface CurrentUserResponse {
    username: string;
}

export class AuthService {
    private static readonly BASE_URL = "/api/auth";

    static async register(request: RegisterRequest): Promise<AuthResponse> {
        const response = await axios.post(`${this.BASE_URL}/register`, request);
        return response.data;
    }

    static async login(request: LoginRequest): Promise<LoginResponse> {
        const response = await axios.post(`${this.BASE_URL}/login`, request);
        return response.data.data;
    }

    static async verifyOtp(otp_token: string): Promise<OtpVerifyResponse> {
        const response = await axios.post(`${this.BASE_URL}/login/verify-otp`, { otp_token });
        return response.data;
    }

    static async logout(): Promise<LogoutResponse> {
        const response = await axios.post(`${this.BASE_URL}/logout`);
        return response.data;
    }

    static async getCurrentUser(): Promise<CurrentUserResponse> {
        const response = await axios.get(`${this.BASE_URL}/me`);
        return response.data.data;
    }
}
