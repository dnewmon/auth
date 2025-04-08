import axios from "axios";

// Client-side model (no database ID)
export interface CredentialRequest {
    service_name: string;
    service_url?: string;
    username: string;
    password: string;
    notes?: string;
    master_password: string;
    category?: string;
}

// Server-side model (includes database ID)
export interface Credential {
    id: number;
    service_name: string;
    service_url?: string;
    username: string;
    password?: string;
    notes?: string;
    category?: string;
    created_at: string;
    updated_at: string;
}

export interface MasterVerificationStatus {
    verified: boolean;
    expires_at: number | null;
    time_remaining: number;
}

export class CredentialsService {
    private static readonly BASE_URL = "/api/credentials";

    static async verifyMasterPassword(master_password: string): Promise<{ message: string }> {
        const response = await axios.post(`${this.BASE_URL}/verify-master`, { master_password });
        return response.data.data;
    }

    static async getMasterVerificationStatus(): Promise<MasterVerificationStatus> {
        const response = await axios.get(`${this.BASE_URL}/verify-master/status`);
        return response.data;
    }

    static async create(data: CredentialRequest): Promise<Credential> {
        const response = await axios.post(`${this.BASE_URL}/`, data);
        return response.data;
    }

    static async list(): Promise<Credential[]> {
        const response = await axios.get(`${this.BASE_URL}/`);
        return response.data;
    }

    static async get(id: number, master_password: string): Promise<Credential> {
        const response = await axios.post(`${this.BASE_URL}/${id}`, { master_password });
        return response.data;
    }

    static async update(id: number, data: Partial<CredentialRequest>): Promise<Credential> {
        const response = await axios.put(`${this.BASE_URL}/${id}`, data);
        return response.data;
    }

    static async delete(id: number): Promise<{ message: string }> {
        const response = await axios.delete(`${this.BASE_URL}/${id}`);
        return response.data.data;
    }
}
