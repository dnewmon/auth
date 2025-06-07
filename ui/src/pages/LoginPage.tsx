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
    const [emailMfaCode, setEmailMfaCode] = useState('');
    const [showEmailMfaForm, setShowEmailMfaForm] = useState(false);
    const [emailFallbackAvailable, setEmailFallbackAvailable] = useState(false);

    const [handleLogin, , loginState, loginError] = useApi(async () => {
        const response = await AuthService.login(formData);

        let go_home = true;

        // Check if response is MfaRequiredData by checking if mfa_required exists
        if ('mfa_required' in response) {
            if (response.mfa_required === 'otp') {
                go_home = false;
                setShowOtpForm(true);
                setEmailFallbackAvailable(response.email_fallback_available || false);
            } else if (response.mfa_required === 'email') {
                go_home = false;
                setShowEmailMfaForm(true);
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

    const [handleEmailMfaVerify, , emailMfaState, emailMfaError] = useApi(async () => {
        const response = await AuthService.verifyEmailMfa({ verification_code: emailMfaCode });
        setUsername(formData.username);
        navigate('/');
        return response;
    });

    const [handleSwitchToEmail, , switchToEmailState, switchToEmailError] = useApi(async () => {
        const response = await AuthService.switchToEmailMfa();
        setShowOtpForm(false);
        setShowEmailMfaForm(true);
        setOtpToken('');
        return response;
    });

    return (
        <Container className="mt-5">
            <Row className="justify-content-center">
                <Col md={6}>
                    <Card>
                        <Card.Body>
                            <h2 className="text-center mb-4">Login</h2>
                            <ApiSuspense api_states={[loginState, otpState, emailMfaState, switchToEmailState]} suspense={<Spinner />}>
                                {!showOtpForm && !showEmailMfaForm ? (
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
                                ) : showOtpForm ? (
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
                                            {emailFallbackAvailable && (
                                                <Button
                                                    variant="secondary"
                                                    className="w-100 mt-2"
                                                    onClick={handleSwitchToEmail}
                                                >
                                                    Use Email Verification Instead
                                                </Button>
                                            )}
                                            <Button
                                                variant="link"
                                                className="w-100 mt-2"
                                                onClick={() => {
                                                    setShowOtpForm(false);
                                                    setOtpToken('');
                                                    setEmailFallbackAvailable(false);
                                                }}
                                            >
                                                Back to Login
                                            </Button>
                                        </Form>
                                    </div>
                                ) : (
                                    <div>
                                        <h3 className="text-center mb-4">Enter Email Verification Code</h3>
                                        <p className="text-center text-muted mb-4">
                                            We've sent a 6-digit verification code to your email address. Please check your inbox.
                                        </p>
                                        <Form
                                            onSubmit={(e) => {
                                                e.preventDefault();
                                                handleEmailMfaVerify();
                                            }}
                                        >
                                            <Form.Group className="mb-3">
                                                <Form.Label>Enter the 6-digit code from your email</Form.Label>
                                                <Form.Control
                                                    type="text"
                                                    value={emailMfaCode}
                                                    onChange={(e) => setEmailMfaCode(e.target.value)}
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
                                                    setShowEmailMfaForm(false);
                                                    setEmailMfaCode('');
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
                            <ApiErrorFallback api_error={emailMfaError} />
                            <ApiErrorFallback api_error={switchToEmailError} />
                        </Card.Body>
                    </Card>
                </Col>
            </Row>
        </Container>
    );
}
