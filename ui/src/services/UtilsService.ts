import axios from 'axios';
import { CredentialData } from './CredentialsService';
import { SuccessResponse } from './Responses';

// Request interfaces
export interface ForgotPasswordRequest {
    email: string;
}

export interface ResetPasswordRequest {
    new_password: string;
    recovery_key?: string;
}

export interface RecoverWithKeyRequest {
    email: string;
    recovery_key: string;
    new_password: string;
}

export interface ExportCredentialsRequest {
    export_password: string;
    session_token: string;
}

export interface ImportCredentialsRequest {
    credentials: CredentialData[];
    session_token: string;
}

// Response data interfaces
export interface MessageData {
    message: string;
}

export interface ResetPasswordData extends MessageData {
    credentials_migrated: boolean;
    recovery_keys?: string[];
    recovery_message?: string;
}

export interface RecoverWithKeyData extends MessageData {
    credentials_preserved: boolean;
}

export interface ExportData {
    message?: string;
}

// Response interfaces
export interface MessageResponse extends SuccessResponse<MessageData> {}
export interface ResetPasswordResponse extends SuccessResponse<ResetPasswordData> {}
export interface RecoverWithKeyResponse extends SuccessResponse<RecoverWithKeyData> {}
export interface ExportResponse extends SuccessResponse<ExportData> {}

export class UtilsService {
    private static readonly BASE_URL = '/api/utils';

    static async forgotPassword(email: string): Promise<MessageData> {
        const response = await axios.post<MessageResponse>(`${this.BASE_URL}/forgot-password`, { email });
        return response.data.data;
    }

    static async resetPassword(token: string, newPassword: string, recoveryKey?: string): Promise<ResetPasswordData> {
        const response = await axios.post<ResetPasswordResponse>(`${this.BASE_URL}/reset-password/${token}`, {
            new_password: newPassword,
            recovery_key: recoveryKey,
        });
        return response.data.data;
    }

    static async recoverWithKey(email: string, recoveryKey: string, newPassword: string): Promise<RecoverWithKeyData> {
        const response = await axios.post<RecoverWithKeyResponse>(`${this.BASE_URL}/recover-with-key`, {
            email,
            recovery_key: recoveryKey,
            new_password: newPassword,
        });
        return response.data.data;
    }

    static async exportCredentials(sessionToken: string, exportPassword: string): Promise<Blob> {
        const response = await axios.post(
            `${this.BASE_URL}/export`,
            {
                session_token: sessionToken,
                export_password: exportPassword,
            },
            {
                responseType: 'blob',
            }
        );
        return response.data;
    }

    static async importCredentials(request: ImportCredentialsRequest): Promise<MessageData> {
        const response = await axios.post<MessageResponse>(`${this.BASE_URL}/import`, request);
        return response.data.data;
    }
}
