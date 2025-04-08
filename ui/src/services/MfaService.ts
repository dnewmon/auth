import axios, { AxiosResponse } from "axios";

export interface ClientMfaStatus {
    otp_enabled: boolean;
    email_mfa_enabled: boolean;
}

export interface SetupOtpResponse {
    provisioning_uri: string;
    qr_code_png_base64: string;
}

export class MfaService {
    private static readonly BASE_URL = "/api/security";

    public static async getMfaStatus(): Promise<ClientMfaStatus> {
        const response = await axios.get(`${this.BASE_URL}/mfa/status`);
        return response.data.data;
    }

    public static async setupOtp(password: string): Promise<SetupOtpResponse> {
        const response = await axios.post(`${this.BASE_URL}/otp/setup`, { password });
        return response.data.data;
    }

    public static async verifyOtp(token: string): Promise<void> {
        await axios.post(`${this.BASE_URL}/otp/verify-enable`, { otp_token: token });
    }

    public static async disableOtp(password: string): Promise<void> {
        await axios.post(`${this.BASE_URL}/otp/disable`, { password });
    }

    public static async enableEmailMfa(password: string): Promise<void> {
        await axios.post(`${this.BASE_URL}/mfa/email/enable`, { password });
    }

    public static async disableEmailMfa(password: string): Promise<void> {
        await axios.post(`${this.BASE_URL}/mfa/email/disable`, { password });
    }
}
