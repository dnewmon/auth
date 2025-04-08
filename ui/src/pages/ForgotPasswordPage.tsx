import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Container, Row, Col, Card, Form, Button, Alert } from "react-bootstrap";
import { UtilsService } from "../services/UtilsService";
import { useApi } from "../react-utilities";

export const ForgotPasswordPage: React.FC = () => {
    const navigate = useNavigate();
    const [email, setEmail] = useState("");
    const [resetSent, setResetSent] = useState(false);

    const [handleForgotPassword, response, state, error] = useApi(async () => {
        await UtilsService.forgotPassword({ email });
        setResetSent(true);
    });

    return (
        <Container className="mt-5">
            <Row className="justify-content-center">
                <Col md={6}>
                    <Card>
                        <Card.Body>
                            <h2 className="text-center mb-4">Forgot Password</h2>
                            {!resetSent ? (
                                <Form
                                    onSubmit={(e) => {
                                        e.preventDefault();
                                        handleForgotPassword();
                                    }}
                                >
                                    <Form.Group className="mb-3">
                                        <Form.Label>Email Address</Form.Label>
                                        <Form.Control type="email" value={email} onChange={(e) => setEmail(e.target.value)} required placeholder="Enter your email address" />
                                    </Form.Group>
                                    <Button variant="primary" type="submit" className="w-100">
                                        Send Reset Link
                                    </Button>
                                    <div className="text-center mt-3">
                                        <Button variant="link" onClick={() => navigate("/login")}>
                                            Back to Login
                                        </Button>
                                    </div>
                                </Form>
                            ) : (
                                <div className="text-center">
                                    <Alert variant="success">If an account with that email exists, a password reset link has been sent.</Alert>
                                    <Button variant="primary" onClick={() => navigate("/login")} className="mt-3">
                                        Return to Login
                                    </Button>
                                </div>
                            )}
                            {error && (
                                <Alert variant="danger" className="mt-3">
                                    {error.message}
                                </Alert>
                            )}
                        </Card.Body>
                    </Card>
                </Col>
            </Row>
        </Container>
    );
};
