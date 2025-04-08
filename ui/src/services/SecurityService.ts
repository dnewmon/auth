import axios from 'axios';

export interface OtpSetupResponse {
    provisioning_uri: string;
    qr_code_png_base64: string;
    message: string;
}

export class SecurityService {
    private static readonly BASE_URL = '/api/security';

    // OTP Methods
    static async setupOtp(password: string): Promise<OtpSetupResponse> {
        const response = await axios.post(`${this.BASE_URL}/otp/setup`, { password });
        return response.data.data;
    }

    static async verifyAndEnableOtp(otp_token: string): Promise<{ message: string }> {
        const response = await axios.post(`${this.BASE_URL}/otp/verify-enable`, { otp_token });
        return response.data.data;
    }

    static async disableOtp(password: string): Promise<{ message: string }> {
        const response = await axios.post(`${this.BASE_URL}/otp/disable`, { password });
        return response.data.data;
    }

    // Email MFA Methods
    static async enableEmailMfa(password: string): Promise<{ message: string }> {
        const response = await axios.post(`${this.BASE_URL}/mfa/email/enable`, { password });
        return response.data.data;
    }

    static async disableEmailMfa(password: string): Promise<{ message: string }> {
        const response = await axios.post(`${this.BASE_URL}/mfa/email/disable`, { password });
        return response.data.data;
    }
}
