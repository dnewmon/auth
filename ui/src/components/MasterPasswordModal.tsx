import React, { useState } from "react";
import { Modal, Button, Form, FloatingLabel } from "react-bootstrap";
import { Lock, Unlock, Download } from "react-bootstrap-icons";

interface MasterPasswordModalProps {
    show: boolean;
    onHide: () => void;
    onVerify: (password: string) => Promise<void>;
    mode?: "verify" | "export";
}

export function MasterPasswordModal({ show, onHide, onVerify, mode = "verify" }: MasterPasswordModalProps) {
    const [password, setPassword] = useState("");
    const [isSubmitting, setIsSubmitting] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSubmitting(true);
        try {
            await onVerify(password);
            setPassword("");
            onHide();
        } finally {
            setIsSubmitting(false);
        }
    };

    const title = mode === "verify" ? "Unlock Credentials" : "Export Credentials";
    const submitText = mode === "verify" ? "Unlock" : "Export";
    const icon = mode === "verify" ? <Lock className="me-2" /> : <Download className="me-2" />;
    const password_title = mode === "verify" ? "Master Password" : "Export Password";

    return (
        <Modal show={show} onHide={onHide}>
            <Modal.Header closeButton>
                <Modal.Title>
                    {icon}
                    {title}
                </Modal.Title>
            </Modal.Header>
            <Modal.Body>
                <Form onSubmit={handleSubmit}>
                    <FloatingLabel label={password_title} className="mb-3">
                        <Form.Control type="password" placeholder={password_title} value={password} onChange={(e) => setPassword(e.target.value)} required autoFocus />
                    </FloatingLabel>
                </Form>
            </Modal.Body>
            <Modal.Footer>
                <Button variant="secondary" onClick={onHide}>
                    Cancel
                </Button>
                <Button variant="primary" onClick={handleSubmit} disabled={isSubmitting}>
                    {isSubmitting ? "Processing..." : submitText}
                </Button>
            </Modal.Footer>
        </Modal>
    );
}
