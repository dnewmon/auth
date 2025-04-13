import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Container, Row, Col, Card, Form, Button, Alert, Spinner } from 'react-bootstrap';
import { ShieldLock } from 'react-bootstrap-icons';
import { UtilsService } from '../services/UtilsService';
import { ApiErrorFallback, ApiSuspense, useApi } from '../react-utilities';

export default function AccountRecoveryPage() {
    const navigate = useNavigate();
    const [email, setEmail] = useState('');
    const [recoveryKey, setRecoveryKey] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [passwordError, setPasswordError] = useState('');
    const [recoverySuccess, setRecoverySuccess] = useState(false);

    const [handleRecovery, _response, state, error] = useApi(async () => {
        if (newPassword !== confirmPassword) {
            setPasswordError('Passwords do not match');
            return;
        }
        setPasswordError('');

        const result = await UtilsService.recoverWithKey(email, recoveryKey, newPassword);
        setRecoverySuccess(true);
        return result;
    });

    const validateAndSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        handleRecovery();
    };

    return (
        <Container className="mt-5">
            <Row className="justify-content-center">
                <Col md={6}>
                    <Card>
                        <Card.Body>
                            <h2 className="text-center mb-4">Account Recovery</h2>
                            <ApiErrorFallback api_error={error} />
                            <ApiSuspense api_states={[state]} suspense={<Spinner className="d-block mx-auto" />}>
                                {!recoverySuccess ? (
                                    <>
                                        <Alert variant="info" className="mb-4">
                                            <Alert.Heading>
                                                <ShieldLock className="me-2" />
                                                Account Recovery with Recovery Key
                                            </Alert.Heading>
                                            <p>
                                                Use your recovery key to reset your password and maintain access to your stored credentials. This direct method bypasses the email
                                                verification step.
                                            </p>
                                        </Alert>

                                        <Form onSubmit={validateAndSubmit}>
                                            <Form.Group className="mb-3">
                                                <Form.Label>Email Address</Form.Label>
                                                <Form.Control
                                                    type="email"
                                                    value={email}
                                                    onChange={(e) => setEmail(e.target.value)}
                                                    required
                                                    placeholder="Enter your email address"
                                                />
                                            </Form.Group>

                                            <Form.Group className="mb-3">
                                                <Form.Label>Recovery Key</Form.Label>
                                                <Form.Control
                                                    type="text"
                                                    value={recoveryKey}
                                                    onChange={(e) => setRecoveryKey(e.target.value)}
                                                    required
                                                    placeholder="Enter your recovery key"
                                                />
                                                <Form.Text className="text-muted">The recovery key you received when setting up your account or changing your password.</Form.Text>
                                            </Form.Group>

                                            <Form.Group className="mb-3">
                                                <Form.Label>New Password</Form.Label>
                                                <Form.Control
                                                    type="password"
                                                    value={newPassword}
                                                    onChange={(e) => setNewPassword(e.target.value)}
                                                    required
                                                    placeholder="Enter new password"
                                                    minLength={8}
                                                />
                                            </Form.Group>

                                            <Form.Group className="mb-3">
                                                <Form.Label>Confirm New Password</Form.Label>
                                                <Form.Control
                                                    type="password"
                                                    value={confirmPassword}
                                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                                    required
                                                    placeholder="Confirm new password"
                                                    minLength={8}
                                                />
                                                {passwordError && <Form.Text className="text-danger">{passwordError}</Form.Text>}
                                            </Form.Group>

                                            <Button variant="primary" type="submit" className="w-100">
                                                Recover Account
                                            </Button>
                                            <div className="text-center mt-3">
                                                <Button variant="link" onClick={() => navigate('/forgot-password')}>
                                                    Back to Password Reset
                                                </Button>
                                                <Button variant="link" onClick={() => navigate('/login')}>
                                                    Back to Login
                                                </Button>
                                            </div>
                                        </Form>
                                    </>
                                ) : (
                                    <div className="text-center">
                                        <Alert variant="success">
                                            <Alert.Heading>Account Recovered Successfully</Alert.Heading>
                                            <p>Your password has been reset and your credentials have been preserved.</p>
                                            <hr />
                                            <p className="mb-0">You can now log in with your new password.</p>
                                        </Alert>
                                        <Button variant="primary" onClick={() => navigate('/login')} className="mt-3">
                                            Go to Login
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
