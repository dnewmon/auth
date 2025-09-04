import React, { createContext, useContext, useEffect, useState } from 'react';
import { MasterVerificationData } from './services/CredentialsService';
import { useSessionStorage } from './react-utilities';
import { decryptAndUnpackage, encryptAndPackage, generateRandomPassword } from './crypto';

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
    const [verificationKey, setVerificationKey] = useSessionStorage<string>('verification-key', '');
    const [verificationData, setVerificationData] = useSessionStorage<string>('verification-data', '');

    const updateMasterPassword = (password: string) => {
        setMasterPassword(password);

        if (password !== '') {
            const verificationKey = generateRandomPassword();
            setVerificationKey(verificationKey);

            encryptAndPackage(password, verificationKey).then((verificationData) => {
                setVerificationData(verificationData);
            });
        } else {
            setVerificationKey('');
            setVerificationData('');
        }
    };

    const readMasterPassword = () => {
        if (verificationData !== '' && verificationKey !== '') {
            decryptAndUnpackage(verificationData, verificationKey).then((password) => {
                setMasterPassword(password.plaintext);
            });
        }
    };

    useEffect(() => {
        if (masterPassword === '' && verificationData !== '' && verificationKey !== '') {
            readMasterPassword();
        }
    }, [masterPassword, verificationData, verificationKey]);

    const [verificationStatus, setVerificationStatus] = useState<MasterVerificationData>({
        verified: false,
        expires_at: null,
        time_remaining: 0,
    });

    const updateVerificationStatus = (status: MasterVerificationData) => {
        setVerificationStatus(status);

        if (!status.verified) {
            updateMasterPassword('');
        }
    };

    return (
        <AppContext.Provider
            value={{
                username,
                setUsername,
                masterPassword,
                setMasterPassword: updateMasterPassword,
                verificationStatus,
                setVerificationStatus: updateVerificationStatus,
            }}
        >
            {children}
        </AppContext.Provider>
    );
};
