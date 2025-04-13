export interface SuccessResponse<T = any> {
    status: 'success';
    message: string;
    data: T;
}

export interface ErrorResponse {
    status: 'error';
    message: string;
}

export interface CredentialData {
    id: number;
    name: string;
    username: string;
    password: string;
    url?: string;
    notes?: string;
    created_at: string;
    updated_at: string;
}

export interface CredentialsResponse extends SuccessResponse<CredentialData[]> {}

export interface ExportData {
    file_url: string;
}

export interface ExportResponse extends SuccessResponse<ExportData> {}

export interface SecurityData {
    password_strength: number;
    password_breached: boolean;
}

export interface SecurityResponse extends SuccessResponse<SecurityData> {}
