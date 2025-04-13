import { useAppContext } from '../AppContext';
import { useNavigate } from 'react-router-dom';
import { Container, Card, Button } from 'react-bootstrap';

export default function HomePage() {
    const { username } = useAppContext();
    const navigate = useNavigate();

    return (
        <Container>
            <Card className="mt-4">
                <Card.Body>
                    <Card.Title>Welcome to Password Manager</Card.Title>
                    {username ? (
                        <>
                            <Card.Text>You are logged in as {username}</Card.Text>
                            <Button variant="primary" onClick={() => navigate('/credentials')}>
                                View Credentials
                            </Button>
                            <Button variant="secondary" className="ms-2" onClick={() => navigate('/account')}>
                                Account Settings
                            </Button>
                        </>
                    ) : (
                        <>
                            <Card.Text>Please log in to manage your credentials</Card.Text>
                            <Button variant="primary" onClick={() => navigate('/login')}>
                                Login
                            </Button>
                        </>
                    )}
                </Card.Body>
            </Card>
        </Container>
    );
}
