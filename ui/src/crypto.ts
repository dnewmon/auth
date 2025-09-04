/**
 * Browser-based cryptography utilities for RSA encryption/decryption
 * Uses Web Crypto API for secure cryptographic operations
 */

export interface EncryptedPackage {
    encryptedData: Uint8Array;
    salt: Uint8Array;
    iv: Uint8Array;
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}

export interface DecryptedPackage {
    plaintext: string;
    salt: Uint8Array;
}

/**
 * Generate a cryptographically secure random salt
 * @param length Length of the salt in bytes (default: 32)
 * @returns Random salt as Uint8Array
 */
export async function generateSalt(length: number = 32): Promise<Uint8Array> {
    const salt = new Uint8Array(length);
    crypto.getRandomValues(salt);
    return salt;
}

/**
 * Generate RSA key pair for encryption/decryption
 * @param modulusLength RSA key size in bits (default: 2048)
 * @returns Promise containing public and private keys
 */
export async function generateRSAKeyPair(modulusLength: number = 2048): Promise<CryptoKeyPair> {
    return await crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: modulusLength,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true, // extractable
        ['encrypt', 'decrypt']
    );
}

/**
 * Derive a symmetric key from password and salt using PBKDF2
 * @param password User password
 * @param salt Random salt
 * @param iterations Number of iterations (default: 100000)
 * @returns Derived key as CryptoKey
 */
async function deriveKey(password: string, salt: Uint8Array, iterations: number = 100000): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    const baseKey = await crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, ['deriveBits', 'deriveKey']);

    return await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: iterations,
            hash: 'SHA-256',
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypt plaintext message and package with RSA keys and salt
 * @param plaintext Message to encrypt
 * @param password User password for key derivation
 * @returns Binary string containing all encrypted data
 */
export async function encryptAndPackage(plaintext: string, password: string): Promise<string> {
    try {
        // Generate components
        const salt = await generateSalt(32);
        const rsaKeyPair = await generateRSAKeyPair(2048);
        const iv = crypto.getRandomValues(new Uint8Array(12)); // 96 bits for AES-GCM

        // Derive symmetric key from password and salt
        const symmetricKey = await deriveKey(password, salt);

        // Encrypt the plaintext with AES-GCM
        const encoder = new TextEncoder();
        const plaintextBuffer = encoder.encode(plaintext);

        const encryptedData = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
            },
            symmetricKey,
            plaintextBuffer
        );

        // Export RSA keys to raw format
        const publicKeyBuffer = await crypto.subtle.exportKey('spki', rsaKeyPair.publicKey);
        const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', rsaKeyPair.privateKey);

        // Create package structure
        const encryptedPackage: EncryptedPackage = {
            encryptedData: new Uint8Array(encryptedData),
            salt: salt,
            iv: iv,
            publicKey: new Uint8Array(publicKeyBuffer),
            privateKey: new Uint8Array(privateKeyBuffer),
        };

        // Convert to binary string
        return packageToBinaryString(encryptedPackage);
    } catch (error) {
        throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

/**
 * Decrypt binary string and extract plaintext
 * @param binaryString Binary string containing encrypted package
 * @param password User password for key derivation
 * @returns Decrypted plaintext and salt
 */
export async function decryptAndUnpackage(binaryString: string, password: string): Promise<DecryptedPackage> {
    try {
        // Parse binary string back to package
        const encryptedPackage = binaryStringToPackage(binaryString);

        // Derive symmetric key from password and salt
        const symmetricKey = await deriveKey(password, encryptedPackage.salt);

        // Decrypt the data
        const decryptedBuffer = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: encryptedPackage.iv,
            },
            symmetricKey,
            encryptedPackage.encryptedData
        );

        // Convert back to string
        const decoder = new TextDecoder();
        const plaintext = decoder.decode(decryptedBuffer);

        return {
            plaintext,
            salt: encryptedPackage.salt,
        };
    } catch (error) {
        throw new Error(`Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

/**
 * Convert EncryptedPackage to binary string
 * @param encryptedPackage Encrypted package to serialize
 * @returns Binary string representation
 */
function packageToBinaryString(encryptedPackage: EncryptedPackage): string {
    // Create a structured format with lengths and data
    const components = [encryptedPackage.salt, encryptedPackage.iv, encryptedPackage.publicKey, encryptedPackage.privateKey, encryptedPackage.encryptedData];

    // Calculate total size needed
    let totalSize = 4; // Number of components
    components.forEach((component) => {
        totalSize += 4; // Length of component
        totalSize += component.length; // Component data
    });

    // Create buffer
    const buffer = new ArrayBuffer(totalSize);
    const view = new DataView(buffer);
    let offset = 0;

    // Write number of components
    view.setUint32(offset, components.length, false);
    offset += 4;

    // Write each component
    components.forEach((component) => {
        view.setUint32(offset, component.length, false);
        offset += 4;

        const uint8View = new Uint8Array(buffer, offset, component.length);
        uint8View.set(component);
        offset += component.length;
    });

    // Convert to binary string
    return arrayBufferToBinaryString(buffer);
}

/**
 * Convert binary string back to EncryptedPackage
 * @param binaryString Binary string to deserialize
 * @returns Encrypted package
 */
function binaryStringToPackage(binaryString: string): EncryptedPackage {
    const buffer = binaryStringToArrayBuffer(binaryString);
    const view = new DataView(buffer);
    let offset = 0;

    // Read number of components
    const numComponents = view.getUint32(offset, false);
    offset += 4;

    if (numComponents !== 5) {
        throw new Error('Invalid package format: expected 5 components');
    }

    // Read each component
    const salt = readComponent(buffer, view, offset);
    offset += 4 + salt.length;

    const iv = readComponent(buffer, view, offset);
    offset += 4 + iv.length;

    const publicKey = readComponent(buffer, view, offset);
    offset += 4 + publicKey.length;

    const privateKey = readComponent(buffer, view, offset);
    offset += 4 + privateKey.length;

    const encryptedData = readComponent(buffer, view, offset);

    return {
        encryptedData,
        salt,
        iv,
        publicKey,
        privateKey,
    };
}

/**
 * Helper function to read a component from buffer
 */
function readComponent(buffer: ArrayBuffer, view: DataView, offset: number): Uint8Array {
    const length = view.getUint32(offset, false);
    return new Uint8Array(buffer, offset + 4, length);
}

/**
 * Convert ArrayBuffer to binary string
 * @param buffer ArrayBuffer to convert
 * @returns Binary string
 */
function arrayBufferToBinaryString(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return binary;
}

/**
 * Convert binary string to ArrayBuffer
 * @param binaryString Binary string to convert
 * @returns ArrayBuffer
 */
function binaryStringToArrayBuffer(binaryString: string): ArrayBuffer {
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Utility function to generate a random password
 * @param length Length of password (default: 32)
 * @returns Random password string
 */
export function generateRandomPassword(length: number = 32): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    const randomValues = new Uint8Array(length);
    crypto.getRandomValues(randomValues);

    for (let i = 0; i < length; i++) {
        password += charset[randomValues[i] % charset.length];
    }

    return password;
}

/**
 * Utility function to validate password strength
 * @param password Password to validate
 * @returns Object with validation results
 */
export function validatePassword(password: string): {
    isValid: boolean;
    score: number;
    feedback: string[];
} {
    const feedback: string[] = [];
    let score = 0;

    if (password.length < 8) {
        feedback.push('Password must be at least 8 characters long');
    } else {
        score += Math.min(password.length * 2, 20);
    }

    if (/[a-z]/.test(password)) score += 5;
    else feedback.push('Include lowercase letters');

    if (/[A-Z]/.test(password)) score += 5;
    else feedback.push('Include uppercase letters');

    if (/[0-9]/.test(password)) score += 5;
    else feedback.push('Include numbers');

    if (/[^A-Za-z0-9]/.test(password)) score += 5;
    else feedback.push('Include special characters');

    const isValid = score >= 20 && password.length >= 8;

    return {
        isValid,
        score: Math.min(score, 100),
        feedback,
    };
}
