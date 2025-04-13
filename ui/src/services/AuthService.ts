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
    recovery_keys: string[];
    recovery_message: string;
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
export interface LogoutResponse extends SuccessResponse<LogoutData> {}
export interface CurrentUserResponse extends SuccessResponse<CurrentUserData> {}
export interface RecoveryKeyStatusResponse extends SuccessResponse<RecoveryKeyStatusData> {}
export interface RegenerateRecoveryKeysResponse extends SuccessResponse<RegenerateRecoveryKeysData> {}

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
}
