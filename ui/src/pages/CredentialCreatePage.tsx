import React, { useState } from 'react';
import { Container, Button, Form, FloatingLabel, Row, Col, Card, Toast } from 'react-bootstrap';
import { useNavigate } from 'react-router-dom';
import { CredentialRequest } from '../services/CredentialsService';
import { useApi, ApiErrorFallback, ApiSuspense, ApiState } from '../react-utilities';
import { useAppContext } from '../AppContext';
import { CredentialsService } from '../services/CredentialsService';
import { Eye, EyeSlash, Clipboard, CheckCircle, Dice1 } from 'react-bootstrap-icons';
import { Breadcrumb } from '../components/Breadcrumb';
import { MasterPasswordRequired } from '../components/MasterPasswordRequired';

const generatePassword = (length: number = 20): string => {
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    const allChars = uppercase + lowercase + numbers + symbols;
    let password = '';

    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += symbols[Math.floor(Math.random() * symbols.length)];

    for (let i = password.length; i < length; i++) {
        password += allChars[Math.floor(Math.random() * allChars.length)];
    }

    return password
        .split('')
        .sort(() => Math.random() - 0.5)
        .join('');
};

export default function CredentialCreatePage() {
    const navigate = useNavigate();
    const { masterPassword } = useAppContext();

    const [serviceName, setServiceName] = useState('');
    const [serviceUrl, setServiceUrl] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [notes, setNotes] = useState('');
    const [category, setCategory] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [showToast, setShowToast] = useState(false);

    const [handleCreate, , createState, createError] = useApi(async (data: CredentialRequest) => {
        await CredentialsService.create(data);
        navigate('/credentials');
    });

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        await handleCreate({
            service_name: serviceName,
            service_url: serviceUrl || undefined,
            username,
            password,
            notes: notes || undefined,
            category: category || undefined,
            master_password: masterPassword,
        });
    };

    const handleCopyPassword = () => {
        navigator.clipboard.writeText(password);
        setShowToast(true);
    };

    return (
        <Container>
            <ApiErrorFallback api_error={createError} />

            <Breadcrumb
                items={[
                    { label: 'Credentials', href: '/credentials' },
                    { label: 'Add New Credential', active: true },
                ]}
            />

            <MasterPasswordRequired>
                <Row className="mb-4">
                    <Col>
                        <h2>Add New Credential</h2>
                    </Col>
                </Row>

                <Row className="justify-content-center">
                    <Col md={8} lg={6}>
                        <Card>
                            <Card.Body>
                                <Form onSubmit={handleSubmit}>
                                    <FloatingLabel label="Category (optional)" className="mb-3">
                                        <Form.Control type="text" placeholder="Category" value={category} onChange={(e) => setCategory(e.target.value)} />
                                    </FloatingLabel>

                                    <FloatingLabel label="Service Name" className="mb-3">
                                        <Form.Control type="text" placeholder="Service Name" value={serviceName} onChange={(e) => setServiceName(e.target.value)} required />
                                    </FloatingLabel>

                                    <FloatingLabel label="Service URL (optional)" className="mb-3">
                                        <Form.Control type="url" placeholder="Service URL" value={serviceUrl} onChange={(e) => setServiceUrl(e.target.value)} />
                                    </FloatingLabel>

                                    <FloatingLabel label="Username" className="mb-3">
                                        <Form.Control type="text" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} required />
                                    </FloatingLabel>

                                    <div className="input-group align-items-stretch mb-3">
                                        <FloatingLabel label="Password">
                                            <Form.Control
                                                type={showPassword ? 'text' : 'password'}
                                                value={password}
                                                onChange={(e) => setPassword(e.target.value)}
                                                required
                                                className="form-control font-monospace"
                                            />
                                        </FloatingLabel>
                                        <Button variant="outline-secondary" onClick={() => setShowPassword(!showPassword)}>
                                            {showPassword ? <EyeSlash /> : <Eye />}
                                        </Button>
                                        <Button variant="outline-secondary" onClick={handleCopyPassword}>
                                            <Clipboard />
                                        </Button>
                                        <Button variant="outline-secondary" onClick={() => setPassword(generatePassword())} title="Generate random password">
                                            <Dice1 />
                                        </Button>
                                    </div>

                                    <Toast onClose={() => setShowToast(false)} show={showToast} delay={3000} autohide className="mb-3">
                                        <Toast.Body className="d-flex align-items-center">
                                            <CheckCircle className="text-success me-2" />
                                            Password copied to clipboard!
                                        </Toast.Body>
                                    </Toast>

                                    <FloatingLabel label="Notes (optional)" className="mb-3">
                                        <Form.Control
                                            className="font-monospace"
                                            as="textarea"
                                            placeholder="Notes"
                                            value={notes}
                                            onChange={(e) => setNotes(e.target.value)}
                                            style={{ height: '200px' }}
                                        />
                                    </FloatingLabel>

                                    <div className="d-flex justify-content-end gap-2">
                                        <Button variant="secondary" onClick={() => navigate('/credentials')} disabled={createState === ApiState.Loading}>
                                            Cancel
                                        </Button>
                                        <ApiSuspense
                                            api_states={[createState]}
                                            suspense={
                                                <Button variant="primary" disabled>
                                                    Creating...
                                                </Button>
                                            }
                                        >
                                            <Button variant="primary" type="submit" disabled={createState === ApiState.Loading}>
                                                Create Credential
                                            </Button>
                                        </ApiSuspense>
                                    </div>
                                </Form>
                            </Card.Body>
                        </Card>
                    </Col>
                </Row>
            </MasterPasswordRequired>
        </Container>
    );
}
