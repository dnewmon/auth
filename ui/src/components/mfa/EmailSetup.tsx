import React, { useState } from "react";
import { Modal, Form, Button } from "react-bootstrap";
import { useApi, ApiErrorFallback, ApiSuspense } from "../../react-utilities";
import { MfaService } from "../../services/MfaService";

interface EmailSetupProps {
    email_mfa_enabled: boolean;
    show: boolean;
    onClose: () => void;
    onSuccess: () => void;
}

export default function EmailSetup({ email_mfa_enabled, show, onClose, onSuccess }: EmailSetupProps) {
    const [password, setPassword] = useState("");

    const [enableEmailMfa, , enableState, enableError] = useApi(
        async () => {
            await MfaService.enableEmailMfa(password);
            onSuccess();
            onClose();
        },
        () => {
            setPassword("");
        }
    );

    const [disableEmailMfa, , disableState, disableError] = useApi(
        async () => {
            await MfaService.disableEmailMfa(password);
            onSuccess();
            onClose();
        },
        () => {
            setPassword("");
        }
    );

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (email_mfa_enabled) {
            disableEmailMfa();
        } else {
            enableEmailMfa();
        }
    };

    return (
        <Modal show={show} onHide={onClose}>
            <Modal.Header closeButton>
                <Modal.Title>{email_mfa_enabled ? "Disable Email MFA" : "Enable Email MFA"}</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                <ApiErrorFallback api_error={enableError || disableError} />
                <Form onSubmit={handleSubmit}>
                    <Form.FloatingLabel label="Password">
                        <Form.Control type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                    </Form.FloatingLabel>
                    <div className="mt-3">
                        <ApiSuspense
                            api_states={[enableState, disableState]}
                            suspense={
                                <Button variant="primary" disabled>
                                    Processing...
                                </Button>
                            }
                        >
                            <Button variant="primary" type="submit">
                                {email_mfa_enabled ? "Disable" : "Enable"}
                            </Button>
                        </ApiSuspense>
                    </div>
                </Form>
            </Modal.Body>
        </Modal>
    );
}
