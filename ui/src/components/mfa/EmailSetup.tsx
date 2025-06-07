import React, { useState } from "react";
import { Modal, Form, Button, Alert } from "react-bootstrap";
import { useApi, ApiErrorFallback, ApiSuspense } from "../../react-utilities";
import { MfaService } from "../../services/MfaService";
import { AuthService } from "../../services/AuthService";

interface EmailSetupProps {
    email_mfa_enabled: boolean;
    email_verified: boolean;
    show: boolean;
    onClose: () => void;
    onSuccess: () => void;
}

export default function EmailSetup({ email_mfa_enabled, email_verified, show, onClose, onSuccess }: EmailSetupProps) {
    const [password, setPassword] = useState("");
    const [verificationCode, setVerificationCode] = useState("");
    const [showVerificationStep, setShowVerificationStep] = useState(false);

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
            setShowVerificationStep(true);
            setPassword("");
        }
    );

    const [verifyDisableEmailMfa, , verifyDisableState, verifyDisableError] = useApi(
        async () => {
            await MfaService.verifyDisableEmailMfa(verificationCode);
            onSuccess();
            onClose();
        },
        () => {
            setVerificationCode("");
            setShowVerificationStep(false);
        }
    );

    const [resendVerification, , resendState, resendError] = useApi(async () => {
        await AuthService.resendVerificationEmail();
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (showVerificationStep) {
            verifyDisableEmailMfa();
        } else if (email_mfa_enabled) {
            disableEmailMfa();
        } else {
            enableEmailMfa();
        }
    };

    const handleClose = () => {
        setPassword("");
        setVerificationCode("");
        setShowVerificationStep(false);
        onClose();
    };

    return (
        <Modal show={show} onHide={handleClose}>
            <Modal.Header closeButton>
                <Modal.Title>
                    {showVerificationStep 
                        ? "Verify Disable Request" 
                        : email_mfa_enabled 
                            ? "Disable Email MFA" 
                            : "Enable Email MFA"
                    }
                </Modal.Title>
            </Modal.Header>
            <Modal.Body>
                <ApiErrorFallback api_error={enableError || disableError || verifyDisableError || resendError} />
                
                {!email_verified && !email_mfa_enabled && (
                    <Alert variant="warning">
                        <Alert.Heading>Email Verification Required</Alert.Heading>
                        <p>You must verify your email address before enabling email MFA.</p>
                        <Button variant="outline-primary" size="sm" onClick={resendVerification}>
                            Resend Verification Email
                        </Button>
                    </Alert>
                )}

                {showVerificationStep ? (
                    <div>
                        <Alert variant="info">
                            <p>We've sent a verification code to your email. Please enter it below to confirm disabling email MFA.</p>
                        </Alert>
                        <Form onSubmit={handleSubmit}>
                            <Form.FloatingLabel label="Verification Code">
                                <Form.Control 
                                    type="text" 
                                    value={verificationCode} 
                                    onChange={(e) => setVerificationCode(e.target.value)} 
                                    maxLength={6}
                                    pattern="[0-9]{6}"
                                    required 
                                />
                            </Form.FloatingLabel>
                            <div className="mt-3">
                                <ApiSuspense
                                    api_states={[verifyDisableState]}
                                    suspense={
                                        <Button variant="danger" disabled>
                                            Processing...
                                        </Button>
                                    }
                                >
                                    <Button variant="danger" type="submit">
                                        Disable Email MFA
                                    </Button>
                                </ApiSuspense>
                            </div>
                        </Form>
                    </div>
                ) : (
                    <Form onSubmit={handleSubmit}>
                        <Form.FloatingLabel label="Password">
                            <Form.Control 
                                type="password" 
                                value={password} 
                                onChange={(e) => setPassword(e.target.value)} 
                                required 
                            />
                        </Form.FloatingLabel>
                        <div className="mt-3">
                            <ApiSuspense
                                api_states={[enableState, disableState, resendState]}
                                suspense={
                                    <Button variant="primary" disabled>
                                        Processing...
                                    </Button>
                                }
                            >
                                <Button 
                                    variant={email_mfa_enabled ? "danger" : "primary"} 
                                    type="submit"
                                    disabled={!email_verified && !email_mfa_enabled}
                                >
                                    {email_mfa_enabled ? "Send Disable Code" : "Enable"}
                                </Button>
                            </ApiSuspense>
                        </div>
                    </Form>
                )}
            </Modal.Body>
        </Modal>
    );
}
