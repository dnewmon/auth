import axios from 'axios';
import { SuccessResponse } from './Responses';

// Request interfaces
export interface SetupOtpRequest {
    password: string;
}

export interface VerifyOtpRequest {
    otp_token: string;
}

export interface DisableOtpRequest {
    password: string;
}

export interface EmailMfaRequest {
    password: string;
}

export interface VerifyEmailMfaDisableRequest {
    verification_code: string;
}

// Response data interfaces
export interface MfaStatusData {
    otp_enabled: boolean;
    email_mfa_enabled: boolean;
    email_verified: boolean;
}

export interface SetupOtpData {
    provisioning_uri: string;
    qr_code_png_base64: string;
    message: string;
}

export interface MessageData {
    message: string;
}

// Response interfaces
export interface MfaStatusResponse extends SuccessResponse<MfaStatusData> {}
export interface SetupOtpResponse extends SuccessResponse<SetupOtpData> {}
export interface MessageResponse extends SuccessResponse<MessageData> {}

export class MfaService {
    private static readonly BASE_URL = '/api/security';

    public static async getMfaStatus(): Promise<MfaStatusData> {
        const response = await axios.get<MfaStatusResponse>(`${this.BASE_URL}/mfa/status`);
        return response.data.data;
    }

    public static async setupOtp(password: string): Promise<SetupOtpData> {
        const response = await axios.post<SetupOtpResponse>(`${this.BASE_URL}/otp/setup`, { password });
        return response.data.data;
    }

    public static async verifyOtp(token: string): Promise<MessageData> {
        const response = await axios.post<MessageResponse>(`${this.BASE_URL}/otp/verify-enable`, { otp_token: token });
        return response.data.data;
    }

    static async disableOtp(password: string): Promise<MessageData> {
        const response = await axios.post<MessageResponse>(`${this.BASE_URL}/otp/disable`, { password });
        return response.data.data;
    }

    static async enableEmailMfa(password: string): Promise<MessageData> {
        const response = await axios.post<MessageResponse>(`${this.BASE_URL}/mfa/email/enable`, { password });
        return response.data.data;
    }

    static async disableEmailMfa(password: string): Promise<MessageData> {
        const response = await axios.post<MessageResponse>(`${this.BASE_URL}/mfa/email/disable`, { password });
        return response.data.data;
    }

    static async verifyDisableEmailMfa(verification_code: string): Promise<MessageData> {
        const response = await axios.post<MessageResponse>(`${this.BASE_URL}/mfa/email/disable/verify`, { verification_code });
        return response.data.data;
    }
}
