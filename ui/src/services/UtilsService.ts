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
    master_password: string;
}

export interface ImportCredentialsRequest {
    credentials: CredentialData[];
    master_password: string;
}

export interface ImportPreviewRequest {
    content: string;
    format?: string;
}

export interface ImportPasswordManagerRequest {
    content: string;
    master_password: string;
    format?: string;
    skip_duplicates?: boolean;
    enforce_policy?: boolean;
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

export interface ImportFormatsData {
    supported_formats: string[];
    format_descriptions: Record<string, string>;
}

export interface ValidationIssue {
    index: number;
    service_name: string;
    issues: string[];
}

export interface ImportPreviewData {
    detected_format: string;
    credential_count: number;
    credentials: CredentialData[];
    validation_issues: ValidationIssue[];
    supported_formats: string[];
}

export interface PolicyViolation {
    service_name: string;
    username: string;
    errors: string[];
}

export interface ImportPasswordManagerData {
    message: string;
    detected_format: string;
    imported_count: number;
    skipped_count: number;
    error_count: number;
    policy_violations?: PolicyViolation[];
}

// Response interfaces
export interface MessageResponse extends SuccessResponse<MessageData> {}
export interface ResetPasswordResponse extends SuccessResponse<ResetPasswordData> {}
export interface RecoverWithKeyResponse extends SuccessResponse<RecoverWithKeyData> {}
export interface ExportResponse extends SuccessResponse<ExportData> {}
export interface ImportFormatsResponse extends SuccessResponse<ImportFormatsData> {}
export interface ImportPreviewResponse extends SuccessResponse<ImportPreviewData> {}
export interface ImportPasswordManagerResponse extends SuccessResponse<ImportPasswordManagerData> {}

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

    static async exportCredentials(masterPassword: string, exportPassword: string): Promise<Blob> {
        const response = await axios.post(
            `${this.BASE_URL}/export`,
            {
                master_password: masterPassword,
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

    static async getImportFormats(): Promise<ImportFormatsData> {
        const response = await axios.get<ImportFormatsResponse>(`${this.BASE_URL}/import/formats`);
        return response.data.data;
    }

    static async previewPasswordManagerImport(request: ImportPreviewRequest): Promise<ImportPreviewData> {
        const response = await axios.post<ImportPreviewResponse>(`${this.BASE_URL}/import/preview`, request);
        return response.data.data;
    }

    static async importFromPasswordManager(request: ImportPasswordManagerRequest): Promise<ImportPasswordManagerData> {
        const response = await axios.post<ImportPasswordManagerResponse>(`${this.BASE_URL}/import/password-manager`, request);
        return response.data.data;
    }
}
