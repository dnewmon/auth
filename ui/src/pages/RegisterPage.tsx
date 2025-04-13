import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Container, Row, Col, Card, Form, Button, Spinner, Alert, Modal } from 'react-bootstrap';
import { AuthService, RegisterData } from '../services/AuthService';
import { ApiErrorFallback, ApiSuspense, useApi } from '../react-utilities';

interface RegisterForm {
    username: string;
    email: string;
    password: string;
}

export default function RegisterPage() {
    const navigate = useNavigate();
    const [formData, setFormData] = useState<RegisterForm>({
        username: '',
        email: '',
        password: '',
    });
    const [registrationComplete, setRegistrationComplete] = useState(false);
    const [userData, setUserData] = useState<RegisterData | null>(null);
    const [showRecoveryKeys, setShowRecoveryKeys] = useState(false);
    const [verificationKey, setVerificationKey] = useState('');
    const [verificationIndex, setVerificationIndex] = useState(-1);
    const [verificationAttempted, setVerificationAttempted] = useState(false);
    const [verificationSuccess, setVerificationSuccess] = useState(false);
    const [recoveryKeysCopied, setRecoveryKeysCopied] = useState(false);

    const [handleRegister, , registerState, registerError] = useApi(async () => {
        const response = await AuthService.register(formData);
        setUserData(response);
        setRegistrationComplete(true);

        // Select a random key index for verification (0 to length-1)
        const randomIndex = Math.floor(Math.random() * response.recovery_keys.length);
        setVerificationIndex(randomIndex);

        return response;
    });

    const handleVerifyKey = () => {
        if (userData && verificationIndex >= 0) {
            setVerificationAttempted(true);
            const keyMatch = verificationKey.trim() === userData.recovery_keys[verificationIndex].trim();
            setVerificationSuccess(keyMatch);
        }
    };

    const handleContinueToLogin = () => {
        navigate('/login');
    };

    const handleCopyKeys = () => {
        if (userData?.recovery_keys) {
            navigator.clipboard
                .writeText(userData.recovery_keys.join('\n'))
                .then(() => setRecoveryKeysCopied(true))
                .catch((err) => console.error('Failed to copy recovery keys: ', err));
        }
    };

    return (
        <Container className="mt-5">
            <Row className="justify-content-center">
                <Col md={6}>
                    <Card>
                        <Card.Body>
                            <h2 className="text-center mb-4">Register</h2>
                            <ApiErrorFallback api_error={registerError} />
                            <ApiSuspense api_states={[registerState]} suspense={<Spinner />}>
                                {!registrationComplete ? (
                                    <Form
                                        onSubmit={(e) => {
                                            e.preventDefault();
                                            handleRegister();
                                        }}
                                    >
                                        <Form.Group className="mb-3">
                                            <Form.Label>Username</Form.Label>
                                            <Form.Control type="text" value={formData.username} onChange={(e) => setFormData({ ...formData, username: e.target.value })} required />
                                        </Form.Group>
                                        <Form.Group className="mb-3">
                                            <Form.Label>Email</Form.Label>
                                            <Form.Control type="email" value={formData.email} onChange={(e) => setFormData({ ...formData, email: e.target.value })} required />
                                        </Form.Group>
                                        <Form.Group className="mb-3">
                                            <Form.Label>Password</Form.Label>
                                            <Form.Control
                                                type="password"
                                                value={formData.password}
                                                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                                                required
                                            />
                                        </Form.Group>
                                        <Button variant="primary" type="submit" className="w-100">
                                            Register
                                        </Button>
                                    </Form>
                                ) : (
                                    <>
                                        <Alert variant="success">
                                            <Alert.Heading>Account Created Successfully!</Alert.Heading>
                                            <p>Your account has been created, but there's one more important step: You need to save your recovery keys.</p>
                                        </Alert>

                                        <Alert variant="warning">
                                            <Alert.Heading>Important: Save Your Recovery Keys</Alert.Heading>
                                            <p>
                                                These recovery keys are crucial for accessing your password vault if you forget your password. Without these keys, you will
                                                permanently lose access to your stored passwords if you forget your master password.
                                            </p>
                                            <hr />
                                            <p className="mb-0">Please store these keys in a secure location like a password manager or printed document in a safe.</p>
                                        </Alert>

                                        <Button variant="primary" className="w-100 mb-3" onClick={() => setShowRecoveryKeys(true)}>
                                            View Recovery Keys
                                        </Button>

                                        {verificationAttempted && (
                                            <Alert variant={verificationSuccess ? 'success' : 'danger'}>
                                                {verificationSuccess
                                                    ? "Verification successful! You've confirmed you have your recovery keys."
                                                    : "Incorrect key entered. Please make sure you've saved your recovery keys correctly."}
                                            </Alert>
                                        )}

                                        {(!verificationAttempted || !verificationSuccess) && (
                                            <Form.Group className="mb-3">
                                                <Form.Label>Please enter Recovery Key #{verificationIndex + 1} to verify you've saved them:</Form.Label>
                                                <Form.Control
                                                    type="text"
                                                    value={verificationKey}
                                                    onChange={(e) => setVerificationKey(e.target.value)}
                                                    placeholder="Enter the recovery key to verify"
                                                    required
                                                />
                                                <Button variant="secondary" className="mt-2" onClick={handleVerifyKey}>
                                                    Verify Key
                                                </Button>
                                            </Form.Group>
                                        )}

                                        <Button variant="success" className="w-100" onClick={handleContinueToLogin} disabled={!verificationSuccess}>
                                            Continue to Login
                                        </Button>
                                    </>
                                )}
                            </ApiSuspense>
                        </Card.Body>
                    </Card>
                </Col>
            </Row>

            {/* Recovery Keys Modal */}
            <Modal show={showRecoveryKeys} onHide={() => setShowRecoveryKeys(false)} backdrop="static" keyboard={false}>
                <Modal.Header>
                    <Modal.Title>Your Recovery Keys</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Alert variant="danger">
                        <Alert.Heading>Warning!</Alert.Heading>
                        <p>
                            These keys will only be shown to you ONCE. Save them immediately! You will need one of these keys to recover your account if you forget your password.
                        </p>
                    </Alert>

                    <div className="bg-light p-3 mb-3 recovery-keys-container">
                        {userData?.recovery_keys.map((key, index) => (
                            <div key={index} className="mb-2">
                                <strong>Key {index + 1}:</strong> {key}
                            </div>
                        ))}
                    </div>

                    <Button variant="secondary" className="w-100 mb-2" onClick={handleCopyKeys}>
                        {recoveryKeysCopied ? 'Copied!' : 'Copy All Keys'}
                    </Button>

                    <p className="text-center mt-3">{userData?.recovery_message}</p>
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="primary" onClick={() => setShowRecoveryKeys(false)}>
                        I've Saved My Keys
                    </Button>
                </Modal.Footer>
            </Modal>
        </Container>
    );
}
