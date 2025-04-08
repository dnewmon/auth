import React from "react";
import { Container, Card, Button, Form } from "react-bootstrap";
import { useAppContext } from "../AppContext";
import { useNavigate } from "react-router-dom";

export const AccountPage: React.FC = () => {
    const { username, setUsername } = useAppContext();
    const navigate = useNavigate();

    const handleLogout = () => {
        setUsername(null);
        navigate("/login");
    };

    return (
        <Container>
            <Card className="mt-4">
                <Card.Body>
                    <Card.Title>Account Settings</Card.Title>
                    <Form>
                        <Form.Group className="mb-3">
                            <Form.Label>Username</Form.Label>
                            <Form.Control type="text" value={username || ""} disabled />
                        </Form.Group>
                        <Button variant="danger" onClick={handleLogout}>
                            Logout
                        </Button>
                    </Form>
                </Card.Body>
            </Card>
        </Container>
    );
};
