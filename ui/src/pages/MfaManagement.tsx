import { useState } from 'react';
import { Card, Button, Spinner, Modal, Form, Alert, Row, Col } from 'react-bootstrap';
import { useApi, ApiErrorFallback, useDebouncedEffect, ApiState, ApiSuspense } from '../react-utilities';
import { MfaService } from '../services/MfaService';
import { AuthService } from '../services/AuthService';
import { UtilsService } from '../services/UtilsService';
import OtpSetup from '../components/mfa/OtpSetup';
import EmailSetup from '../components/mfa/EmailSetup';

export default function MfaManagement() {
    const [showOtpSetup, setShowOtpSetup] = useState(false);
    const [showEmailSetup, setShowEmailSetup] = useState(false);
    const [_showRecoveryKeyModal, setShowRecoveryKeyModal] = useState(false);
    const [showRegenerateKeysModal, setShowRegenerateKeysModal] = useState(false);
    const [showDirectRecoveryModal, setShowDirectRecoveryModal] = useState(false);
    const [masterPassword, setMasterPassword] = useState('');
    const [directRecoveryForm, setDirectRecoveryForm] = useState({
        email: '',
        recoveryKey: '',
        newPassword: '',
        confirmPassword: '',
    });
    const [recoveryKeyCopied, setRecoveryKeyCopied] = useState(false);
    const [directRecoverySuccess, setDirectRecoverySuccess] = useState(false);

    const [loadMfaStatus, mfaStatus, mfaStatusState, mfaStatusError] = useApi(async () => {
        const response = await MfaService.getMfaStatus();
        return response;
    });

    const [loadRecoveryKeyStatus, recoveryKeyStatus, recoveryKeyStatusState, recoveryKeyStatusError] = useApi(async () => {
        const response = await AuthService.getRecoveryKeyStatus();
        return response;
    });

    const [regenerateRecoveryKeys, regeneratedKeys, regenerateKeysState, regenerateKeysError] = useApi(async () => {
        if (!masterPassword) {
            throw new Error('Password is required');
        }
        const response = await AuthService.regenerateRecoveryKeys({ password: masterPassword });
        setMasterPassword('');
        setShowRegenerateKeysModal(false);
        return response;
    });

    const [handleDirectRecovery, directRecoveryResponse, directRecoveryState, directRecoveryError] = useApi(async () => {
        if (directRecoveryForm.newPassword !== directRecoveryForm.confirmPassword) {
            throw new Error('Passwords do not match');
        }

        const response = await UtilsService.recoverWithKey(directRecoveryForm.email, directRecoveryForm.recoveryKey, directRecoveryForm.newPassword);

        setDirectRecoverySuccess(true);
        return response;
    });

    // Load MFA and recovery key status when component mounts
    useDebouncedEffect(
        () => {
            if (mfaStatusState === ApiState.NotLoaded) {
                loadMfaStatus();
            }
            if (recoveryKeyStatusState === ApiState.NotLoaded) {
                loadRecoveryKeyStatus();
            }
        },
        [mfaStatusState, recoveryKeyStatusState],
        300
    );

    const handleOtpSuccess = () => {
        loadMfaStatus();
    };

    const handleCopyKeys = () => {
        if (regeneratedKeys?.recovery_keys) {
            navigator.clipboard
                .writeText(regeneratedKeys.recovery_keys.join('\n'))
                .then(() => setRecoveryKeyCopied(true))
                .catch((err) => console.error('Failed to copy recovery keys: ', err));
        }
    };

    const resetDirectRecoveryForm = () => {
        setDirectRecoveryForm({
            email: '',
            recoveryKey: '',
            newPassword: '',
            confirmPassword: '',
        });
        setDirectRecoverySuccess(false);
    };

    return (
        <div className="container py-4">
            <h1 className="mb-4">Account Security Settings</h1>

            <h2 className="mb-3">Two-Factor Authentication</h2>

            <ApiErrorFallback api_error={mfaStatusError} />

            <ApiSuspense api_states={[mfaStatusState]} suspense={<Spinner />}>
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
            </ApiSuspense>

            <Card className="mb-5">
                <Card.Body>
                    <Card.Title>Email Multi-Factor Authentication</Card.Title>
                    <Card.Text>Receive verification codes via email for login and account changes.</Card.Text>
                    {!mfaStatus?.email_verified && (
                        <Alert variant="warning" className="mb-3">
                            <small>Email verification required before enabling email MFA.</small>
                        </Alert>
                    )}
                    {mfaStatus?.email_mfa_enabled ? (
                        <Button variant="danger" onClick={() => setShowEmailSetup(true)}>
                            Disable Email MFA
                        </Button>
                    ) : (
                        <Button 
                            variant="primary" 
                            onClick={() => setShowEmailSetup(true)}
                            disabled={!mfaStatus?.email_verified}
                        >
                            Enable Email MFA
                        </Button>
                    )}
                </Card.Body>
            </Card>

            <h2 className="mb-3">Account Recovery</h2>

            <ApiErrorFallback api_error={recoveryKeyStatusError} />

            <ApiSuspense api_states={[recoveryKeyStatusState]} suspense={<Spinner />}>
                <Card className="mb-4">
                    <Card.Body>
                        <Card.Title>Recovery Keys</Card.Title>
                        <Card.Text>Recovery keys allow you to regain access to your account and stored passwords if you forget your master password.</Card.Text>

                        {recoveryKeyStatus && (
                            <div className="mb-3">
                                <strong>Status: </strong>
                                {recoveryKeyStatus.has_keys ? (
                                    <span className="text-success">
                                        You have {recoveryKeyStatus.total_keys} recovery keys, with {recoveryKeyStatus.unused_keys} unused keys.
                                    </span>
                                ) : (
                                    <span className="text-danger">No recovery keys found. Your account is at risk if you forget your password.</span>
                                )}
                            </div>
                        )}

                        <Row>
                            <Col>
                                <Button variant="primary" onClick={() => setShowRegenerateKeysModal(true)} className="me-2">
                                    Generate New Recovery Keys
                                </Button>
                            </Col>
                        </Row>
                    </Card.Body>
                </Card>

                <Card className="mb-4">
                    <Card.Body>
                        <Card.Title>Direct Recovery</Card.Title>
                        <Card.Text>Use a recovery key to reset your password and preserve access to your stored credentials without email verification.</Card.Text>
                        <Button variant="secondary" onClick={() => setShowDirectRecoveryModal(true)}>
                            Recover Using Key
                        </Button>
                    </Card.Body>
                </Card>
            </ApiSuspense>

            {/* Existing Modals */}
            <OtpSetup otp_enabled={mfaStatus?.otp_enabled || false} show={showOtpSetup} onClose={() => setShowOtpSetup(false)} onSuccess={handleOtpSuccess} />
            <EmailSetup 
                email_mfa_enabled={mfaStatus?.email_mfa_enabled || false} 
                email_verified={mfaStatus?.email_verified || false}
                show={showEmailSetup} 
                onClose={() => setShowEmailSetup(false)} 
                onSuccess={loadMfaStatus} 
            />

            {/* Regenerate Recovery Keys Modal */}
            <Modal show={showRegenerateKeysModal} onHide={() => setShowRegenerateKeysModal(false)}>
                <Modal.Header closeButton>
                    <Modal.Title>Generate New Recovery Keys</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <ApiErrorFallback api_error={regenerateKeysError} />
                    <ApiSuspense api_states={[regenerateKeysState]} suspense={<Spinner />}>
                        <Alert variant="warning">
                            <Alert.Heading>Important Notice</Alert.Heading>
                            <p>Generating new recovery keys will invalidate any existing recovery keys. Make sure you save these new keys in a secure location.</p>
                        </Alert>

                        <Form.Group className="mb-3">
                            <Form.Label>Confirm Master Password</Form.Label>
                            <Form.Control
                                type="password"
                                value={masterPassword}
                                onChange={(e) => setMasterPassword(e.target.value)}
                                placeholder="Enter your master password"
                                required
                            />
                            <Form.Text className="text-muted">Your password is required to generate new recovery keys.</Form.Text>
                        </Form.Group>
                    </ApiSuspense>
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="secondary" onClick={() => setShowRegenerateKeysModal(false)}>
                        Cancel
                    </Button>
                    <Button variant="primary" onClick={regenerateRecoveryKeys} disabled={!masterPassword}>
                        Generate New Keys
                    </Button>
                </Modal.Footer>
            </Modal>

            {/* Recovery Keys Display Modal */}
            <Modal
                show={regeneratedKeys?.recovery_keys && regeneratedKeys.recovery_keys.length > 0}
                onHide={() => setShowRecoveryKeyModal(false)}
                backdrop="static"
                keyboard={false}
            >
                <Modal.Header>
                    <Modal.Title>Your New Recovery Keys</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Alert variant="danger">
                        <Alert.Heading>Warning!</Alert.Heading>
                        <p>These keys will only be shown once. Save them immediately! You will need one of these keys to recover your account if you forget your password.</p>
                    </Alert>

                    <div className="bg-light p-3 mb-3 recovery-keys-container">
                        {regeneratedKeys?.recovery_keys?.map((key, index) => (
                            <div key={index} className="mb-2">
                                <strong>Key {index + 1}:</strong> {key}
                            </div>
                        ))}
                    </div>

                    <Button variant="secondary" className="w-100 mb-2" onClick={handleCopyKeys}>
                        {recoveryKeyCopied ? 'Copied!' : 'Copy All Keys'}
                    </Button>

                    <p className="text-center mt-3">{regeneratedKeys?.recovery_message}</p>
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="primary" onClick={() => window.location.reload()}>
                        I've Saved My Keys
                    </Button>
                </Modal.Footer>
            </Modal>

            {/* Direct Recovery Modal */}
            <Modal
                show={showDirectRecoveryModal}
                onHide={() => {
                    setShowDirectRecoveryModal(false);
                    resetDirectRecoveryForm();
                }}
                size="lg"
            >
                <Modal.Header closeButton>
                    <Modal.Title>Direct Account Recovery</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <ApiErrorFallback api_error={directRecoveryError} />
                    <ApiSuspense api_states={[directRecoveryState]} suspense={<Spinner />}>
                        {!directRecoverySuccess ? (
                            <>
                                <Alert variant="info">
                                    <Alert.Heading>Recover Account with Recovery Key</Alert.Heading>
                                    <p>
                                        This process allows you to reset your password and maintain access to your stored credentials using one of your recovery keys, without
                                        requiring email verification.
                                    </p>
                                </Alert>

                                <Form
                                    onSubmit={(e) => {
                                        e.preventDefault();
                                        handleDirectRecovery();
                                    }}
                                >
                                    <Form.Group className="mb-3">
                                        <Form.Label>Email Address</Form.Label>
                                        <Form.Control
                                            type="email"
                                            value={directRecoveryForm.email}
                                            onChange={(e) =>
                                                setDirectRecoveryForm({
                                                    ...directRecoveryForm,
                                                    email: e.target.value,
                                                })
                                            }
                                            placeholder="Enter your account email"
                                            required
                                        />
                                    </Form.Group>

                                    <Form.Group className="mb-3">
                                        <Form.Label>Recovery Key</Form.Label>
                                        <Form.Control
                                            type="text"
                                            value={directRecoveryForm.recoveryKey}
                                            onChange={(e) =>
                                                setDirectRecoveryForm({
                                                    ...directRecoveryForm,
                                                    recoveryKey: e.target.value,
                                                })
                                            }
                                            placeholder="Enter one of your recovery keys"
                                            required
                                        />
                                    </Form.Group>

                                    <Form.Group className="mb-3">
                                        <Form.Label>New Password</Form.Label>
                                        <Form.Control
                                            type="password"
                                            value={directRecoveryForm.newPassword}
                                            onChange={(e) =>
                                                setDirectRecoveryForm({
                                                    ...directRecoveryForm,
                                                    newPassword: e.target.value,
                                                })
                                            }
                                            placeholder="Enter your new password"
                                            minLength={8}
                                            required
                                        />
                                    </Form.Group>

                                    <Form.Group className="mb-3">
                                        <Form.Label>Confirm New Password</Form.Label>
                                        <Form.Control
                                            type="password"
                                            value={directRecoveryForm.confirmPassword}
                                            onChange={(e) =>
                                                setDirectRecoveryForm({
                                                    ...directRecoveryForm,
                                                    confirmPassword: e.target.value,
                                                })
                                            }
                                            placeholder="Confirm your new password"
                                            minLength={8}
                                            required
                                        />
                                    </Form.Group>

                                    <Button variant="primary" type="submit" className="w-100">
                                        Recover Account
                                    </Button>
                                </Form>
                            </>
                        ) : (
                            <Alert variant="success">
                                <Alert.Heading>Recovery Successful!</Alert.Heading>
                                <p>
                                    Your password has been reset successfully.
                                    {directRecoveryResponse?.credentials_preserved
                                        ? ' Your stored credentials have been preserved.'
                                        : ' However, your credentials could not be preserved.'}
                                </p>
                                <div className="d-grid gap-2 mt-3">
                                    <Button variant="primary" onClick={() => (window.location.href = '/login')}>
                                        Go to Login
                                    </Button>
                                </div>
                            </Alert>
                        )}
                    </ApiSuspense>
                </Modal.Body>
            </Modal>
        </div>
    );
}
