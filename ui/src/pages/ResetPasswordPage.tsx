import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Container, Row, Col, Card, Form, Button, Alert, Spinner, InputGroup } from 'react-bootstrap';
import { QuestionCircle, InfoCircle } from 'react-bootstrap-icons';
import { UtilsService } from '../services/UtilsService';
import { ApiErrorFallback, ApiSuspense, useApi } from '../react-utilities';

export default function ResetPasswordPage() {
    const navigate = useNavigate();
    const { token } = useParams<{ token: string }>();
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [recoveryKey, setRecoveryKey] = useState('');
    const [isRecoveryKeyValid, setIsRecoveryKeyValid] = useState<boolean | null>(null);
    const [passwordReset, setPasswordReset] = useState(false);
    const [resetData, setResetData] = useState<{ credentials_migrated: boolean; recovery_message?: string }>({ credentials_migrated: false });

    // Validate recovery key format: XXXX-XXXX-XXXX-XXXX
    const validateRecoveryKey = (key: string): boolean => {
        if (!key) return true; // Empty is valid (optional)
        const keyPattern = /^[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$/;
        return keyPattern.test(key);
    };

    // Format the recovery key as user types (add hyphens automatically)
    const formatRecoveryKey = (value: string): string => {
        const cleaned = value.replace(/[^A-Za-z0-9]/g, '');
        const chunks = [];

        for (let i = 0; i < cleaned.length && i < 16; i += 4) {
            chunks.push(cleaned.substring(i, i + 4));
        }

        return chunks.join('-');
    };

    const handleRecoveryKeyChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const formattedKey = formatRecoveryKey(e.target.value);
        setRecoveryKey(formattedKey);
        setIsRecoveryKeyValid(validateRecoveryKey(formattedKey));
    };

    // Update validation state when key changes
    useEffect(() => {
        if (recoveryKey) {
            setIsRecoveryKeyValid(validateRecoveryKey(recoveryKey));
        }
    }, [recoveryKey]);

    const [handleResetPassword, , state, error] = useApi(async () => {
        if (!token) {
            throw new Error('Invalid reset token');
        }
        if (newPassword !== confirmPassword) {
            throw new Error('Passwords do not match');
        }
        if (recoveryKey && !validateRecoveryKey(recoveryKey)) {
            throw new Error('Invalid recovery key format. It should be in the format: XXXX-XXXX-XXXX-XXXX');
        }

        // Include recovery key if provided
        const response = await UtilsService.resetPassword(token, newPassword, recoveryKey || undefined);
        setResetData(response);
        setPasswordReset(true);
    });

    /*
    const getRecoveryKeyValidationState = () => {
        if (recoveryKey === '') return null;
        return isRecoveryKeyValid ? 'success' : 'error';
    };
    */

    return (
        <Container className="mt-5">
            <Row className="justify-content-center">
                <Col md={6}>
                    <Card>
                        <Card.Body>
                            <h2 className="text-center mb-4">Reset Password</h2>
                            <ApiErrorFallback api_error={error} />
                            <ApiSuspense api_states={[state]} suspense={<Spinner />}>
                                {!passwordReset ? (
                                    <>
                                        <Alert variant="info">
                                            <Alert.Heading>Protect Your Stored Passwords</Alert.Heading>
                                            <p>
                                                If you have a recovery key, enter it below to maintain access to your stored passwords. Without a recovery key, you'll lose access
                                                to all your stored credentials when resetting your password.
                                            </p>
                                            <hr />
                                            <p className="mb-0">
                                                <InfoCircle className="me-2" />
                                                Don't have a recovery key?{' '}
                                                <Button variant="link" className="p-0" onClick={() => navigate('/account/recovery')} style={{ verticalAlign: 'baseline' }}>
                                                    Try direct recovery instead
                                                </Button>
                                            </p>
                                        </Alert>

                                        <Form
                                            onSubmit={(e) => {
                                                e.preventDefault();
                                                handleResetPassword();
                                            }}
                                        >
                                            <Form.Group className="mb-3">
                                                <Form.Label>
                                                    Recovery Key (Optional)
                                                    <OverlayTrigger
                                                        placement="right"
                                                        overlay={
                                                            <Tooltip>
                                                                Your recovery key was provided when you created your account. It has 16 characters in format: XXXX-XXXX-XXXX-XXXX
                                                            </Tooltip>
                                                        }
                                                    >
                                                        <QuestionCircle className="ms-2" style={{ cursor: 'pointer' }} />
                                                    </OverlayTrigger>
                                                </Form.Label>
                                                <InputGroup hasValidation>
                                                    <Form.Control
                                                        type="text"
                                                        value={recoveryKey}
                                                        onChange={handleRecoveryKeyChange}
                                                        placeholder="XXXX-XXXX-XXXX-XXXX"
                                                        isInvalid={isRecoveryKeyValid === false}
                                                        isValid={recoveryKey !== '' && isRecoveryKeyValid === true}
                                                        aria-describedby="recoveryKeyHelpBlock"
                                                        maxLength={19} // 16 chars + 3 hyphens
                                                    />
                                                    <Form.Control.Feedback type="invalid">Recovery key must be in format: XXXX-XXXX-XXXX-XXXX</Form.Control.Feedback>
                                                </InputGroup>
                                                <Form.Text id="recoveryKeyHelpBlock" className="text-muted">
                                                    Enter one of your recovery keys to maintain access to your stored passwords. The key format is: <code>XXXX-XXXX-XXXX-XXXX</code>{' '}
                                                    (16 characters with hyphens).
                                                </Form.Text>
                                            </Form.Group>

                                            <hr className="my-4" />

                                            <Form.Group className="mb-3">
                                                <Form.Label>New Password</Form.Label>
                                                <Form.Control
                                                    type="password"
                                                    value={newPassword}
                                                    onChange={(e) => setNewPassword(e.target.value)}
                                                    required
                                                    minLength={8}
                                                    placeholder="Enter your new password"
                                                />
                                            </Form.Group>
                                            <Form.Group className="mb-3">
                                                <Form.Label>Confirm New Password</Form.Label>
                                                <Form.Control
                                                    type="password"
                                                    value={confirmPassword}
                                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                                    required
                                                    minLength={8}
                                                    placeholder="Confirm your new password"
                                                    isInvalid={confirmPassword !== '' && confirmPassword !== newPassword}
                                                />
                                                <Form.Control.Feedback type="invalid">Passwords do not match</Form.Control.Feedback>
                                            </Form.Group>
                                            <Button
                                                variant="primary"
                                                type="submit"
                                                className="w-100"
                                                disabled={(recoveryKey !== '' && !isRecoveryKeyValid) || (confirmPassword !== '' && confirmPassword !== newPassword)}
                                            >
                                                Reset Password
                                            </Button>
                                        </Form>
                                    </>
                                ) : (
                                    <div className="text-center">
                                        <Alert variant="success">
                                            <Alert.Heading>Password Reset Successful</Alert.Heading>
                                            <p>Your password has been successfully reset.</p>
                                            {resetData.credentials_migrated ? (
                                                <p className="mb-0">Your stored passwords have been successfully preserved.</p>
                                            ) : (
                                                <p className="mb-0">Without a valid recovery key, your stored passwords could not be migrated.</p>
                                            )}
                                            {resetData.recovery_message && <p className="mt-2 font-italic">{resetData.recovery_message}</p>}
                                        </Alert>
                                        <Button variant="primary" onClick={() => navigate('/login')} className="mt-3">
                                            Return to Login
                                        </Button>
                                    </div>
                                )}
                            </ApiSuspense>
                        </Card.Body>
                    </Card>
                </Col>
            </Row>
        </Container>
    );
}

// Helper component for the tooltip
const Tooltip = ({ children }: { children: React.ReactNode }) => {
    return (
        <div
            style={{
                backgroundColor: 'rgba(0, 0, 0, 0.85)',
                color: 'white',
                borderRadius: '3px',
                padding: '2px 10px',
                marginTop: '5px',
                fontSize: '14px',
            }}
        >
            {children}
        </div>
    );
};

// Helper component for creating tooltips
const OverlayTrigger = ({ children, overlay, placement }: { children: React.ReactNode; overlay: React.ReactNode; placement: string }) => {
    const [showTooltip, setShowTooltip] = useState(false);

    return (
        <span style={{ position: 'relative', display: 'inline-block' }} onMouseEnter={() => setShowTooltip(true)} onMouseLeave={() => setShowTooltip(false)}>
            {children}
            {showTooltip && (
                <div
                    style={{
                        position: 'absolute',
                        zIndex: 1000,
                        ...(placement === 'right' ? { left: '100%', top: '0' } : {}),
                        ...(placement === 'top' ? { bottom: '100%', left: '50%', transform: 'translateX(-50%)' } : {}),
                        ...(placement === 'bottom' ? { top: '100%', left: '50%', transform: 'translateX(-50%)' } : {}),
                        ...(placement === 'left' ? { right: '100%', top: '0' } : {}),
                        marginLeft: placement === 'right' ? '5px' : '0',
                        width: '250px',
                    }}
                >
                    {overlay}
                </div>
            )}
        </span>
    );
};
