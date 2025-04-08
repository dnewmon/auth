import React, { useState } from "react";
import { Modal, Button, Form, FloatingLabel, Toast } from "react-bootstrap";
import { Credential, CredentialRequest } from "../services/CredentialsService";
import { Eye, EyeSlash, Clipboard, CheckCircle, Dice1 } from "react-bootstrap-icons";

interface CredentialModalProps {
    show: boolean;
    onHide: () => void;
    mode: "create" | "view" | "edit";
    credential?: Credential;
    onSave?: (data: Omit<CredentialRequest, "master_password">) => Promise<void>;
}

// Function to generate a secure random password
const generatePassword = (length: number = 20): string => {
    const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lowercase = "abcdefghijklmnopqrstuvwxyz";
    const numbers = "0123456789";
    const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    const allChars = uppercase + lowercase + numbers + symbols;
    let password = "";

    // Ensure at least one character from each category
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += symbols[Math.floor(Math.random() * symbols.length)];

    // Fill the rest randomly
    for (let i = password.length; i < length; i++) {
        password += allChars[Math.floor(Math.random() * allChars.length)];
    }

    // Shuffle the password
    return password
        .split("")
        .sort(() => Math.random() - 0.5)
        .join("");
};

export function CredentialModal({ show, onHide, mode, credential, onSave }: CredentialModalProps) {
    // Form state
    const [serviceName, setServiceName] = useState(credential?.service_name || "");
    const [serviceUrl, setServiceUrl] = useState(credential?.service_url || "");
    const [username, setUsername] = useState(credential?.username || "");
    const [password, setPassword] = useState(credential?.password || "");
    const [notes, setNotes] = useState(credential?.notes || "");
    const [category, setCategory] = useState(credential?.category || "");
    const [showPassword, setShowPassword] = useState(false);
    const [showToast, setShowToast] = useState(false);

    // Reset form when modal closes
    const handleClose = () => {
        setServiceName(credential?.service_name || "");
        setServiceUrl(credential?.service_url || "");
        setUsername(credential?.username || "");
        setPassword(credential?.password || "");
        setNotes(credential?.notes || "");
        setCategory(credential?.category || "");
        setShowPassword(false);
        onHide();
    };

    // Handle form submission
    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (onSave) {
            await onSave({
                service_name: serviceName,
                service_url: serviceUrl || undefined,
                username,
                password,
                notes: notes || undefined,
                category: category || undefined,
            });
            handleClose();
        }
    };

    // Handle copying password to clipboard
    const handleCopyPassword = () => {
        navigator.clipboard.writeText(password);
        setShowToast(true);
    };

    const isViewMode = mode === "view";
    const title = {
        create: "Add New Credential",
        view: "View Credential",
        edit: "Edit Credential",
    }[mode];

    return (
        <>
            <Modal show={show} onHide={handleClose} size="lg">
                <Modal.Header closeButton>
                    <Modal.Title>{title}</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    {isViewMode ? (
                        // View mode layout
                        <div className="p-3">
                            {credential?.category && (
                                <>
                                    <h5 className="mt-3">Category</h5>
                                    <p>{credential.category}</p>
                                </>
                            )}
                            <h5>Service Name</h5>
                            <p>{credential?.service_name}</p>

                            {credential?.service_url && (
                                <>
                                    <h5>Service URL</h5>
                                    <p>
                                        <a href={credential.service_url} target="_blank" rel="noopener noreferrer">
                                            {credential.service_url}
                                        </a>
                                    </p>
                                </>
                            )}

                            <h5>Username</h5>
                            <p>{credential?.username}</p>

                            <h5>Password</h5>
                            <div className="d-flex flex-gap-2 align-items-center">
                                <p className="mb-0 me-2 font-monospace">{showPassword ? credential?.password : "••••••••"}</p>
                                <Button variant="outline-secondary" size="sm" onClick={() => setShowPassword(!showPassword)} className="me-2">
                                    {showPassword ? <EyeSlash /> : <Eye />}
                                </Button>
                                <Button variant="outline-secondary" size="sm" onClick={handleCopyPassword}>
                                    <Clipboard />
                                </Button>
                                <Toast onClose={() => setShowToast(false)} show={showToast} delay={3000} autohide className="ms-3">
                                    <Toast.Body className="d-flex align-items-center">
                                        <CheckCircle className="text-success me-2" />
                                        Password copied to clipboard!
                                    </Toast.Body>
                                </Toast>
                            </div>

                            {credential?.notes && (
                                <>
                                    <h5 className="mt-3">Notes</h5>
                                    <pre className="font-monospace">{credential.notes}</pre>
                                </>
                            )}
                        </div>
                    ) : (
                        // Create/Edit mode form
                        <Form onSubmit={handleSubmit}>
                            <FloatingLabel label="Category (optional)" className="mb-3">
                                <Form.Control type="text" placeholder="Category" value={category} onChange={(e) => setCategory(e.target.value)} />
                            </FloatingLabel>
                            <FloatingLabel label="Service Name" className="mb-3">
                                <Form.Control type="text" placeholder="Service Name" value={serviceName} onChange={(e) => setServiceName(e.target.value)} required />
                            </FloatingLabel>

                            <FloatingLabel label="Service URL (optional)" className="mb-3">
                                <Form.Control type="url" placeholder="Service URL" value={serviceUrl} onChange={(e) => setServiceUrl(e.target.value)} />
                            </FloatingLabel>

                            <FloatingLabel label="Username" className="mb-3">
                                <Form.Control type="text" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} required />
                            </FloatingLabel>

                            <div className="input-group align-items-stretch mb-3">
                                <FloatingLabel label="Password">
                                    <Form.Control
                                        type={showPassword ? "text" : "password"}
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        required
                                        className="form-control font-monospace"
                                    />
                                </FloatingLabel>
                                <Button variant="outline-secondary" onClick={() => setShowPassword(!showPassword)}>
                                    {showPassword ? <EyeSlash /> : <Eye />}
                                </Button>
                                <Button variant="outline-secondary" onClick={handleCopyPassword}>
                                    <Clipboard />
                                </Button>
                                <Button variant="outline-secondary" onClick={() => setPassword(generatePassword())} title="Generate random password">
                                    <Dice1 />
                                </Button>
                            </div>
                            <Toast onClose={() => setShowToast(false)} show={showToast} delay={3000} autohide className="mb-3">
                                <Toast.Body className="d-flex align-items-center">
                                    <CheckCircle className="text-success me-2" />
                                    Password copied to clipboard!
                                </Toast.Body>
                            </Toast>

                            <FloatingLabel label="Notes (optional)" className="mb-3">
                                <Form.Control
                                    className="font-monospace"
                                    as="textarea"
                                    placeholder="Notes"
                                    value={notes}
                                    onChange={(e) => setNotes(e.target.value)}
                                    style={{ height: "300px" }}
                                />
                            </FloatingLabel>
                        </Form>
                    )}
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="secondary" onClick={handleClose}>
                        Close
                    </Button>
                    {!isViewMode && (
                        <Button variant="primary" type="submit" onClick={handleSubmit}>
                            {mode === "create" ? "Create" : "Save Changes"}
                        </Button>
                    )}
                </Modal.Footer>
            </Modal>

            {/* <div style={{ position: "fixed", bottom: 20, right: 20 }}> */}
            {/* </div> */}
        </>
    );
}
