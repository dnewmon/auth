import axios from 'axios';
import { SuccessResponse } from './Responses';

// Request interfaces
export interface LoginRequest {
    username: string;
    password: string;
}

export interface RegisterRequest {
    username: string;
    password: string;
    email: string;
}

export interface VerifyOtpRequest {
    otp_token: string;
}

export interface VerifyEmailMfaRequest {
    verification_code: string;
}

export interface RegenerateRecoveryKeysRequest {
    password: string;
}

// Response data interfaces
export interface UserData {
    id: number;
    username: string;
    email: string;
}

export interface MfaRequiredData {
    mfa_required: 'otp' | 'email';
    email_fallback_available?: boolean;
}

export interface LoginSuccessData {
    message: string;
}

export interface OtpVerifyData {
    message: string;
}

export interface RegisterData {
    id: number;
    username: string;
    email: string;
    email_verified: boolean;
    recovery_keys: string[];
    recovery_message: string;
    verification_message: string;
}

export interface EmailVerificationStatusData {
    email_verified: boolean;
}

export interface LogoutData {
    message: string;
}

export interface CurrentUserData {
    username: string;
}

export interface RecoveryKeyStatusData {
    total_keys: number;
    unused_keys: number;
    has_keys: boolean;
}

export interface RegenerateRecoveryKeysData {
    recovery_keys: string[];
    recovery_message: string;
}

// Response interfaces
export interface LoginResponse extends SuccessResponse<MfaRequiredData | LoginSuccessData> {}
export interface RegisterResponse extends SuccessResponse<RegisterData> {}
export interface VerifyOtpResponse extends SuccessResponse<OtpVerifyData> {}
export interface VerifyEmailMfaResponse extends SuccessResponse<OtpVerifyData> {}
export interface LogoutResponse extends SuccessResponse<LogoutData> {}
export interface CurrentUserResponse extends SuccessResponse<CurrentUserData> {}
export interface RecoveryKeyStatusResponse extends SuccessResponse<RecoveryKeyStatusData> {}
export interface RegenerateRecoveryKeysResponse extends SuccessResponse<RegenerateRecoveryKeysData> {}
export interface EmailVerificationStatusResponse extends SuccessResponse<EmailVerificationStatusData> {}
export interface MessageResponse extends SuccessResponse<{ message: string }> {}

export class AuthService {
    private static readonly BASE_URL = '/api/auth';

    static async register(data: RegisterRequest): Promise<RegisterData> {
        const response = await axios.post<RegisterResponse>(`${this.BASE_URL}/register`, data);
        return response.data.data;
    }

    static async login(data: LoginRequest): Promise<MfaRequiredData | LoginSuccessData> {
        const response = await axios.post<LoginResponse>(`${this.BASE_URL}/login`, data);
        return response.data.data;
    }

    static async verifyOtp(data: VerifyOtpRequest): Promise<OtpVerifyData> {
        const response = await axios.post<VerifyOtpResponse>(`${this.BASE_URL}/login/verify-otp`, data);
        return response.data.data;
    }

    static async verifyEmailMfa(data: VerifyEmailMfaRequest): Promise<OtpVerifyData> {
        const response = await axios.post<VerifyEmailMfaResponse>(`${this.BASE_URL}/login/verify-email`, data);
        return response.data.data;
    }

    static async logout(): Promise<LogoutData> {
        const response = await axios.post<LogoutResponse>(`${this.BASE_URL}/logout`);
        return response.data.data;
    }

    static async getCurrentUser(): Promise<CurrentUserData> {
        const response = await axios.get<CurrentUserResponse>(`${this.BASE_URL}/me`);
        return response.data.data;
    }

    static async getRecoveryKeyStatus(): Promise<RecoveryKeyStatusData> {
        const response = await axios.get<RecoveryKeyStatusResponse>(`${this.BASE_URL}/recovery-keys`);
        return response.data.data;
    }

    static async regenerateRecoveryKeys(data: RegenerateRecoveryKeysRequest): Promise<RegenerateRecoveryKeysData> {
        const response = await axios.post<RegenerateRecoveryKeysResponse>(`${this.BASE_URL}/recovery-keys`, data);
        return response.data.data;
    }

    static async getEmailVerificationStatus(): Promise<EmailVerificationStatusData> {
        const response = await axios.get<EmailVerificationStatusResponse>(`${this.BASE_URL}/email-verification-status`);
        return response.data.data;
    }

    static async resendVerificationEmail(): Promise<{ message: string }> {
        const response = await axios.post<MessageResponse>(`${this.BASE_URL}/resend-verification`);
        return response.data.data;
    }

    static async switchToEmailMfa(): Promise<{ message: string }> {
        const response = await axios.post<MessageResponse>(`${this.BASE_URL}/login/switch-to-email`);
        return response.data.data;
    }
}
