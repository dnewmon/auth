import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Container, Row, Col, Card, Form, Button, Alert, Spinner } from 'react-bootstrap';
import { InfoCircle, ShieldLock } from 'react-bootstrap-icons';
import { UtilsService } from '../services/UtilsService';
import { ApiErrorFallback, ApiSuspense, useApi } from '../react-utilities';

export default function ForgotPasswordPage() {
    const navigate = useNavigate();
    const [email, setEmail] = useState('');
    const [resetSent, setResetSent] = useState(false);

    const [handleForgotPassword, , state, error] = useApi(async () => {
        await UtilsService.forgotPassword(email);
        setResetSent(true);
    });

    return (
        <Container className="mt-5">
            <Row className="justify-content-center">
                <Col md={6}>
                    <Card>
                        <Card.Body>
                            <h2 className="text-center mb-4">Forgot Password</h2>
                            <ApiErrorFallback api_error={error} />
                            <ApiSuspense api_states={[state]} suspense={<Spinner />}>
                                {!resetSent ? (
                                    <>
                                        <Alert variant="warning" className="mb-4">
                                            <Alert.Heading>
                                                <ShieldLock className="me-2" />
                                                Important Security Information
                                            </Alert.Heading>
                                            <p>
                                                All your stored passwords are encrypted with a key that is protected by your master password. If you reset your password without
                                                using a recovery key, <strong>you will permanently lose access to all your stored passwords</strong>.
                                            </p>
                                            <hr />
                                            <div className="d-flex justify-content-between">
                                                <div>
                                                    <InfoCircle className="me-2" />
                                                    Have a recovery key?
                                                </div>
                                                <Button variant="outline-primary" size="sm" onClick={() => navigate('/account/recovery')}>
                                                    Use Direct Recovery
                                                </Button>
                                            </div>
                                        </Alert>

                                        <Form
                                            onSubmit={(e) => {
                                                e.preventDefault();
                                                handleForgotPassword();
                                            }}
                                        >
                                            <Form.Group className="mb-3">
                                                <Form.Label>Email Address</Form.Label>
                                                <Form.Control
                                                    type="email"
                                                    value={email}
                                                    onChange={(e) => setEmail(e.target.value)}
                                                    required
                                                    placeholder="Enter your email address"
                                                />
                                                <Form.Text className="text-muted">You'll receive an email with a link to reset your password.</Form.Text>
                                            </Form.Group>
                                            <Alert variant="info" className="mb-3">
                                                <small>
                                                    When resetting your password, you'll be asked for a recovery key to maintain access to your stored passwords. If you don't have
                                                    a recovery key, you'll still be able to reset your password, but you'll lose access to your stored credentials.
                                                </small>
                                            </Alert>
                                            <Button variant="primary" type="submit" className="w-100">
                                                Send Reset Link
                                            </Button>
                                            <div className="text-center mt-3">
                                                <Button variant="link" onClick={() => navigate('/login')}>
                                                    Back to Login
                                                </Button>
                                            </div>
                                        </Form>
                                    </>
                                ) : (
                                    <div className="text-center">
                                        <Alert variant="success">
                                            <Alert.Heading>Reset Email Sent</Alert.Heading>
                                            <p>If an account with that email exists, a password reset link has been sent.</p>
                                            <hr />
                                            <p className="mb-0">
                                                <strong>Important:</strong> To preserve your stored passwords during reset, you'll need one of your recovery keys. Please check your
                                                records for your recovery keys before proceeding with the reset.
                                            </p>
                                        </Alert>
                                        <div className="d-flex justify-content-between mt-3">
                                            <Button variant="outline-secondary" onClick={() => navigate('/login')}>
                                                Return to Login
                                            </Button>
                                            <Button variant="outline-primary" onClick={() => navigate('/account/recovery')}>
                                                Try Direct Recovery
                                            </Button>
                                        </div>
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
