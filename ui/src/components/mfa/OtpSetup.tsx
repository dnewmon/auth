import React, { useState } from 'react';
import { Form, Button, Modal, Image, Spinner } from 'react-bootstrap';
import { MfaService } from '../../services/MfaService';
import { ApiErrorFallback, ApiSuspense, useApi } from '../../react-utilities';

interface OtpSetupProps {
    show: boolean;
    onClose: () => void;
    onSuccess: () => void;
    otp_enabled: boolean;
}

export default function OtpSetup({ show, onClose, onSuccess, otp_enabled }: OtpSetupProps) {
    const [step, setStep] = useState<'password' | 'qr' | 'verify'>('password');
    const [password, setPassword] = useState('');
    const [otpToken, setOtpToken] = useState('');
    const [qrCode, setQrCode] = useState('');

    const [setupOtp, , setupState, setupError] = useApi(async () => {
        const response = await MfaService.setupOtp(password);
        setQrCode(response.qr_code_png_base64);
        setStep('qr');
    });

    const [disableOtp, , disableState, disableError] = useApi(async () => {
        await MfaService.disableOtp(password);
        onSuccess();
        onClose();
    });

    const [verifyOtp, , verifyState, verifyError] = useApi(async () => {
        await MfaService.verifyOtp(otpToken);
        onSuccess();
        onClose();
    });

    const handlePasswordSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (otp_enabled) {
            await disableOtp();
        } else {
            await setupOtp();
        }
    };

    const handleVerifySubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        await verifyOtp();
    };

    const handleClose = () => {
        setStep('password');
        setPassword('');
        setOtpToken('');
        setQrCode('');
        onClose();
    };

    return (
        <Modal show={show} onHide={handleClose} centered size="lg">
            <Modal.Header closeButton>
                <Modal.Title>{otp_enabled ? 'Disable' : 'Setup'} Two-Factor Authentication</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                <ApiErrorFallback api_error={setupError} />
                <ApiErrorFallback api_error={disableError} />
                <ApiErrorFallback api_error={verifyError} />
                <ApiSuspense api_states={[setupState, disableState, verifyState]} suspense={<Spinner />}>
                    {step === 'password' && (
                        <Form onSubmit={handlePasswordSubmit}>
                            <Form.Group className="mb-3">
                                <Form.Label>Enter your password to {otp_enabled ? 'disable' : 'continue'}</Form.Label>
                                <Form.Control type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                            </Form.Group>
                            <Button variant="primary" type="submit">
                                {otp_enabled ? 'Disable' : 'Continue'}
                            </Button>
                        </Form>
                    )}

                    {!otp_enabled && step === 'qr' && (
                        <div className="text-center">
                            <p>Scan this QR code with your authenticator app:</p>
                            <Image src={`data:image/png;base64,${qrCode}`} alt="OTP QR Code" />
                            <Button variant="primary" className="mt-3" onClick={() => setStep('verify')}>
                                I've scanned the QR code
                            </Button>
                        </div>
                    )}

                    {!otp_enabled && step === 'verify' && (
                        <Form onSubmit={handleVerifySubmit}>
                            <Form.Group className="mb-3">
                                <Form.Label>Enter the 6-digit code from your authenticator app</Form.Label>
                                <Form.Control type="text" value={otpToken} onChange={(e) => setOtpToken(e.target.value)} pattern="[0-9]{6}" maxLength={6} required />
                            </Form.Group>
                            <Button variant="primary" type="submit">
                                Verify
                            </Button>
                        </Form>
                    )}
                </ApiSuspense>
            </Modal.Body>
        </Modal>
    );
}
