import axios from "axios";

export interface ForgotPasswordRequest {
    email: string;
}

export interface ResetPasswordRequest {
    new_password: string;
}

export interface ExportCredentialsRequest {
    export_password: string;
    master_password: string;
}

export class UtilsService {
    private static readonly BASE_URL = "/api/utils";

    static async forgotPassword(request: ForgotPasswordRequest): Promise<{ message: string }> {
        const response = await axios.post(`${this.BASE_URL}/forgot-password`, request);
        return response.data.data;
    }

    static async resetPassword(token: string, request: ResetPasswordRequest): Promise<{ message: string }> {
        const response = await axios.post(`${this.BASE_URL}/reset-password/${token}`, request);
        return response.data.data;
    }

    static async exportCredentials(request: ExportCredentialsRequest): Promise<Blob> {
        const response = await axios.post(`${this.BASE_URL}/export`, request, {
            responseType: "blob",
        });
        return response.data;
    }
}
