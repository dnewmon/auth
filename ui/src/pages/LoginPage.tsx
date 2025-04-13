import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Container, Row, Col, Card, Form, Button, Spinner } from 'react-bootstrap';
import { useAppContext } from '../AppContext';
import { AuthService } from '../services/AuthService';
import { ApiErrorFallback, ApiSuspense, useApi } from '../react-utilities';

interface LoginForm {
    username: string;
    password: string;
}

export default function LoginPage() {
    const navigate = useNavigate();
    const { setUsername } = useAppContext();
    const [formData, setFormData] = useState<LoginForm>({
        username: '',
        password: '',
    });
    const [otpToken, setOtpToken] = useState('');
    const [showOtpForm, setShowOtpForm] = useState(false);

    const [handleLogin, , loginState, loginError] = useApi(async () => {
        const response = await AuthService.login(formData);

        let go_home = true;

        // Check if response is MfaRequiredData by checking if mfa_required exists
        if ('mfa_required' in response) {
            if (response.mfa_required === 'otp') {
                go_home = false;
                setShowOtpForm(true);
            }
        }

        if (go_home) {
            setUsername(formData.username);
            navigate('/');
        }
    });

    const [handleOtpVerify, , otpState, otpError] = useApi(async () => {
        const response = await AuthService.verifyOtp({ otp_token: otpToken });
        setUsername(formData.username);
        navigate('/');
        return response;
    });

    return (
        <Container className="mt-5">
            <Row className="justify-content-center">
                <Col md={6}>
                    <Card>
                        <Card.Body>
                            <h2 className="text-center mb-4">Login</h2>
                            <ApiSuspense api_states={[loginState, otpState]} suspense={<Spinner />}>
                                {!showOtpForm ? (
                                    <Form
                                        onSubmit={(e) => {
                                            e.preventDefault();
                                            handleLogin();
                                        }}
                                    >
                                        <Form.Group className="mb-3">
                                            <Form.Label>Username</Form.Label>
                                            <Form.Control type="text" value={formData.username} onChange={(e) => setFormData({ ...formData, username: e.target.value })} required />
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
                                            Login
                                        </Button>
                                        <div className="text-center mt-3">
                                            <Link to="/register">Don't have an account? Register here</Link>
                                            <div className="mt-2">
                                                <Link to="/forgot-password">Forgot your password?</Link>
                                            </div>
                                        </div>
                                    </Form>
                                ) : (
                                    <div>
                                        <h3 className="text-center mb-4">Enter OTP Code</h3>
                                        <Form
                                            onSubmit={(e) => {
                                                e.preventDefault();
                                                handleOtpVerify();
                                            }}
                                        >
                                            <Form.Group className="mb-3">
                                                <Form.Label>Enter the 6-digit code from your authenticator app</Form.Label>
                                                <Form.Control
                                                    type="text"
                                                    value={otpToken}
                                                    onChange={(e) => setOtpToken(e.target.value)}
                                                    pattern="[0-9]{6}"
                                                    maxLength={6}
                                                    required
                                                />
                                            </Form.Group>
                                            <Button variant="primary" type="submit" className="w-100">
                                                Verify
                                            </Button>
                                            <Button
                                                variant="link"
                                                className="w-100 mt-2"
                                                onClick={() => {
                                                    setShowOtpForm(false);
                                                    setOtpToken('');
                                                }}
                                            >
                                                Back to Login
                                            </Button>
                                        </Form>
                                    </div>
                                )}
                            </ApiSuspense>
                            <ApiErrorFallback api_error={loginError} />
                            <ApiErrorFallback api_error={otpError} />
                        </Card.Body>
                    </Card>
                </Col>
            </Row>
        </Container>
    );
}
