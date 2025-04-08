import React, { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Container, Row, Col, Card, Form, Button, Alert } from "react-bootstrap";
import { UtilsService } from "../services/UtilsService";
import { useApi } from "../react-utilities";

export const ResetPasswordPage: React.FC = () => {
    const navigate = useNavigate();
    const { token } = useParams<{ token: string }>();
    const [newPassword, setNewPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [passwordReset, setPasswordReset] = useState(false);

    const [handleResetPassword, response, state, error] = useApi(async () => {
        if (!token) {
            throw new Error("Invalid reset token");
        }
        if (newPassword !== confirmPassword) {
            throw new Error("Passwords do not match");
        }
        await UtilsService.resetPassword(token, { new_password: newPassword });
        setPasswordReset(true);
    });

    return (
        <Container className="mt-5">
            <Row className="justify-content-center">
                <Col md={6}>
                    <Card>
                        <Card.Body>
                            <h2 className="text-center mb-4">Reset Password</h2>
                            {!passwordReset ? (
                                <Form
                                    onSubmit={(e) => {
                                        e.preventDefault();
                                        handleResetPassword();
                                    }}
                                >
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
                                        />
                                    </Form.Group>
                                    <Button variant="primary" type="submit" className="w-100">
                                        Reset Password
                                    </Button>
                                </Form>
                            ) : (
                                <div className="text-center">
                                    <Alert variant="success">Your password has been successfully reset.</Alert>
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
