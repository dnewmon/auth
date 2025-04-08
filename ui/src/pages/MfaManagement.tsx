import React, { useState } from "react";
import { Card, Form, Button } from "react-bootstrap";
import { useApi, ApiErrorFallback, useDebouncedEffect, ApiState } from "../react-utilities";
import { MfaService } from "../services/MfaService";
import OtpSetup from "../components/mfa/OtpSetup";
import EmailSetup from "../components/mfa/EmailSetup";

export default function MfaManagement() {
    const [showOtpSetup, setShowOtpSetup] = useState(false);
    const [showEmailSetup, setShowEmailSetup] = useState(false);

    const [loadMfaStatus, mfaStatus, mfaStatusState, mfaStatusError] = useApi(async () => {
        const response = await MfaService.getMfaStatus();
        return response;
    });

    // Load MFA status when component mounts or when state is NotLoaded
    useDebouncedEffect(
        () => {
            if (mfaStatusState === ApiState.NotLoaded) {
                loadMfaStatus();
            }
        },
        [mfaStatusState],
        300
    );

    const handleOtpSuccess = () => {
        loadMfaStatus();
    };

    return (
        <div className="container py-4">
            <h1 className="mb-4">Two-Factor Authentication</h1>

            <ApiErrorFallback api_error={mfaStatusError} />

            <Card className="mb-4">
                <Card.Body>
                    <Card.Title>Authenticator App (OTP)</Card.Title>
                    <Card.Text>Use an authenticator app like Google Authenticator or Authy to generate time-based one-time passwords.</Card.Text>
                    {mfaStatus?.otp_enabled ? (
                        <Button variant="danger" onClick={() => setShowOtpSetup(true)}>
                            Disable OTP
                        </Button>
                    ) : (
                        <Button variant="primary" onClick={() => setShowOtpSetup(true)}>
                            Enable OTP
                        </Button>
                    )}
                </Card.Body>
            </Card>

            <Card>
                <Card.Body>
                    <Card.Title>Email Notifications</Card.Title>
                    <Card.Text>Receive email notifications when someone logs into your account.</Card.Text>
                    {mfaStatus?.email_mfa_enabled ? (
                        <Button variant="danger" onClick={() => setShowEmailSetup(true)}>
                            Disable Email MFA
                        </Button>
                    ) : (
                        <Button variant="primary" onClick={() => setShowEmailSetup(true)}>
                            Enable Email MFA
                        </Button>
                    )}
                </Card.Body>
            </Card>

            <OtpSetup otp_enabled={mfaStatus?.otp_enabled || false} show={showOtpSetup} onClose={() => setShowOtpSetup(false)} onSuccess={handleOtpSuccess} />

            <EmailSetup email_mfa_enabled={mfaStatus?.email_mfa_enabled || false} show={showEmailSetup} onClose={() => setShowEmailSetup(false)} onSuccess={loadMfaStatus} />
        </div>
    );
}
