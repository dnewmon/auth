import axios from 'axios';
import { SuccessResponse } from './Responses';

// Request interfaces
export interface CredentialRequest {
    master_password: string;
    service_name: string;
    service_url?: string;
    username: string;
    password: string;
    notes?: string;
    category?: string;
}

export interface CredentialUpdateRequest {
    master_password: string;
    service_name?: string;
    service_url?: string;
    username?: string;
    password?: string;
    notes?: string;
    category?: string;
}

export interface GetCredentialRequest {
    master_password: string;
}

export interface VerifyMasterRequest {
    master_password: string;
}

export interface AuditCredentialsRequest {
    master_password: string;
    search_term: string;
}

// Response data interfaces
export interface CredentialData {
    id: number;
    service_name: string;
    service_url?: string;
    username: string;
    password?: string;
    notes?: string;
    category?: string;
    created_at?: string;
    updated_at?: string;
}

export interface CredentialListData {
    id: number;
    service_name: string;
    username: string;
    service_url?: string;
    category?: string;
}

export interface MasterVerificationData {
    verified: boolean;
    expires_at: number | null;
    time_remaining: number;
}

export interface VerifyMasterData {
    message: string;
}

export interface DeleteCredentialData {
    message: string;
}

export interface PasswordData {
    password: string;
}

// Response interfaces
export interface CredentialResponse extends SuccessResponse<CredentialData> {}
export interface CredentialsResponse extends SuccessResponse<CredentialListData[]> {}
export interface MasterVerificationResponse extends SuccessResponse<MasterVerificationData> {}
export interface VerifyMasterResponse extends SuccessResponse<string> {}
export interface DeleteCredentialResponse extends SuccessResponse<string> {}
export interface PasswordResponse extends SuccessResponse<PasswordData> {}

export class CredentialsService {
    private static readonly BASE_URL = '/api/credentials';

    static async verifyMasterPassword(master_password: string): Promise<string> {
        const response = await axios.post<VerifyMasterResponse>(`${this.BASE_URL}/verify-master`, { master_password });
        return response.data.data;
    }

    static async getMasterVerificationStatus(): Promise<MasterVerificationData> {
        const response = await axios.get<MasterVerificationResponse>(`${this.BASE_URL}/verify-master/status`);
        return response.data.data;
    }

    static async list(category?: string): Promise<CredentialListData[]> {
        const params = category ? { category } : {};
        const response = await axios.get<CredentialsResponse>(`${this.BASE_URL}/`, { params });
        return response.data.data;
    }

    static async getById(id: number, master_password: string): Promise<CredentialData> {
        const response = await axios.post<CredentialResponse>(`${this.BASE_URL}/${id}`, { master_password });
        return response.data.data;
    }

    static async create(data: CredentialRequest): Promise<CredentialData> {
        const response = await axios.post<CredentialResponse>(`${this.BASE_URL}/`, data);
        return response.data.data;
    }

    static async update(id: number, data: CredentialUpdateRequest): Promise<CredentialData> {
        const response = await axios.put<CredentialResponse>(`${this.BASE_URL}/${id}`, data);
        return response.data.data;
    }

    static async delete(id: number): Promise<string> {
        const response = await axios.delete<DeleteCredentialResponse>(`${this.BASE_URL}/${id}`);
        return response.data.data;
    }

    static async getPassword(id: number, master_password: string): Promise<string> {
        const response = await axios.post<PasswordResponse>(`${this.BASE_URL}/${id}/password`, { master_password });
        return response.data.data.password;
    }

    static async auditPasswords(data: AuditCredentialsRequest): Promise<CredentialListData[]> {
        const response = await axios.post<CredentialsResponse>(`${this.BASE_URL}/audit`, data);
        return response.data.data;
    }
}
