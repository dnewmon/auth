import React, { createContext, useContext, useState } from 'react';
import { MasterVerificationData } from './services/CredentialsService';

interface AppContextType {
    username: string | null;
    setUsername: (username: string | null) => void;
    masterPassword: string;
    setMasterPassword: (password: string) => void;
    verificationStatus: MasterVerificationData;
    setVerificationStatus: (status: MasterVerificationData) => void;
}

const AppContext = createContext<AppContextType>({
    username: null,
    setUsername: () => {},
    masterPassword: '',
    setMasterPassword: () => {},
    verificationStatus: {
        verified: false,
        expires_at: null,
        time_remaining: 0,
    },
    setVerificationStatus: () => {},
});

export const useAppContext = () => useContext(AppContext);

export const AppContextProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [username, setUsername] = useState<string | null>(null);
    const [masterPassword, setMasterPassword] = useState<string>('');
    const [verificationStatus, setVerificationStatus] = useState<MasterVerificationData>({
        verified: false,
        expires_at: null,
        time_remaining: 0,
    });

    return (
        <AppContext.Provider
            value={{
                username,
                setUsername,
                masterPassword,
                setMasterPassword,
                verificationStatus,
                setVerificationStatus,
            }}
        >
            {children}
        </AppContext.Provider>
    );
};
