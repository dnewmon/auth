import React, { useState } from 'react';
import { Container, Button, Form, FloatingLabel, Row, Col, Card, Toast, Spinner } from 'react-bootstrap';
import { useNavigate, useParams } from 'react-router-dom';
import { CredentialRequest } from '../services/CredentialsService';
import { useApi, ApiErrorFallback, ApiSuspense, ApiState, useDebouncedEffect } from '../react-utilities';
import { useAppContext } from '../AppContext';
import { CredentialsService } from '../services/CredentialsService';
import { Eye, EyeSlash, Clipboard, CheckCircle, Dice1, Trash } from 'react-bootstrap-icons';
import { Breadcrumb } from '../components/Breadcrumb';
import { MasterPasswordRequired } from '../components/MasterPasswordRequired';
import { DeleteConfirmationModal } from '../components/DeleteConfirmationModal';
import { copyToClipboard } from '../helpers';

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

export default function CredentialEditPage() {
    const navigate = useNavigate();
    const { id } = useParams<{ id: string }>();
    const { sessionToken, verificationStatus } = useAppContext();

    const [serviceName, setServiceName] = useState('');
    const [serviceUrl, setServiceUrl] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [notes, setNotes] = useState('');
    const [category, setCategory] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [showToast, setShowToast] = useState(false);
    const [showDeleteModal, setShowDeleteModal] = useState(false);

    const [getCredential, credential, getState, getError] = useApi(
        async (credId: number) => {
            const cred = await CredentialsService.getById(credId, sessionToken);
            return cred;
        },
        (cred) => {
            if (cred !== null) {
                setServiceName(cred.service_name || '');
                setServiceUrl(cred.service_url || '');
                setUsername(cred.username || '');
                setPassword(cred.password || '');
                setNotes(cred.notes || '');
                setCategory(cred.category || '');
            }
        }
    );

    const [handleUpdate, , updateState, updateError] = useApi(async (data: CredentialRequest) => {
        if (credential) {
            await CredentialsService.update(credential.id, data);
            navigate('/credentials');
        }
    });

    const [handleDelete, , deleteState, deleteError] = useApi(async () => {
        if (credential) {
            await CredentialsService.delete(credential.id);
            navigate('/credentials');
        }
    });

    useDebouncedEffect(() => {
        if (id && getState === ApiState.NotLoaded && verificationStatus.verified) {
            const credId = parseInt(id, 10);
            if (!isNaN(credId)) {
                getCredential(credId);
            } else {
                navigate('/credentials');
            }
        }
    }, [id, navigate, getCredential, getState, verificationStatus.verified]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        await handleUpdate({
            service_name: serviceName,
            service_url: serviceUrl || undefined,
            username,
            password,
            notes: notes || undefined,
            category: category || undefined,
            session_token: sessionToken,
        });
    };

    const handleCopyPassword = async () => {
        try {
            await copyToClipboard(password);
            setShowToast(true);
        } catch (err) {
            console.error('Failed to copy password:', err);
        }
    };

    const handleDeleteClick = () => {
        setShowDeleteModal(true);
    };

    const handleDeleteConfirm = async () => {
        await handleDelete();
        setShowDeleteModal(false);
    };

    const LoadingSuspense = (
        <Container>
            <div className="text-center mt-4">
                <Spinner animation="border" />
                <p className="mt-2">Loading credential...</p>
            </div>
        </Container>
    );

    return (
        <Container>
            <ApiErrorFallback api_error={getError || updateError || deleteError} />

            <Breadcrumb
                items={[
                    { label: 'Credentials', href: '/credentials' },
                    { label: credential?.service_name || 'Loading...', href: credential ? `/credentials/${credential.id}` : undefined },
                    { label: 'Edit', active: true },
                ]}
            />

            <MasterPasswordRequired>
                <ApiSuspense api_state={getState} suspense={LoadingSuspense}>
                    <Row className="mb-4">
                        <Col>
                            <h2>Edit Credential</h2>
                            {credential && <p className="text-muted">Editing: {credential.service_name}</p>}
                        </Col>
                    </Row>

                    <Row className="justify-content-center">
                        <Col md={12}>
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
                                                spellCheck={false}
                                                style={{ height: '80vh' }}
                                            />
                                        </FloatingLabel>

                                        <div className="d-flex justify-content-between gap-2">
                                            <div>
                                                <ApiSuspense
                                                    api_states={[deleteState]}
                                                    suspense={
                                                        <Button variant="outline-danger" disabled>
                                                            <Spinner animation="border" size="sm" className="me-2" />
                                                            Deleting...
                                                        </Button>
                                                    }
                                                >
                                                    <Button variant="outline-danger" onClick={handleDeleteClick} disabled={deleteState === ApiState.Loading}>
                                                        <Trash className="me-2" />
                                                        Delete
                                                    </Button>
                                                </ApiSuspense>
                                            </div>
                                            <div className="d-flex gap-2">
                                                <Button
                                                    variant="secondary"
                                                    onClick={() => navigate('/credentials')}
                                                    disabled={updateState === ApiState.Loading || deleteState === ApiState.Loading}
                                                >
                                                    Cancel
                                                </Button>
                                                <ApiSuspense
                                                    api_states={[updateState]}
                                                    suspense={
                                                        <Button variant="primary" disabled>
                                                            Saving...
                                                        </Button>
                                                    }
                                                >
                                                    <Button variant="primary" type="submit" disabled={updateState === ApiState.Loading || deleteState === ApiState.Loading}>
                                                        Save Changes
                                                    </Button>
                                                </ApiSuspense>
                                            </div>
                                        </div>
                                    </Form>
                                </Card.Body>
                            </Card>
                        </Col>
                    </Row>
                </ApiSuspense>
            </MasterPasswordRequired>
            {/* Delete Confirmation Modal */}
            {credential && (
                <DeleteConfirmationModal show={showDeleteModal} onHide={() => setShowDeleteModal(false)} onConfirm={handleDeleteConfirm} itemName={credential.service_name} />
            )}
        </Container>
    );
}
