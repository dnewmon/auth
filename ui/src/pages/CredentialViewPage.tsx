import { useState } from 'react';
import { Container, Button, Row, Col, Card, Toast, Spinner } from 'react-bootstrap';
import { useNavigate, useParams } from 'react-router-dom';
import { useApi, ApiErrorFallback, ApiState, useDebouncedEffect, ApiSuspense } from '../react-utilities';
import { useAppContext } from '../AppContext';
import { CredentialsService } from '../services/CredentialsService';
import { Eye, EyeSlash, Clipboard, CheckCircle, Pencil } from 'react-bootstrap-icons';
import { Breadcrumb } from '../components/Breadcrumb';
import { MasterPasswordRequired } from '../components/MasterPasswordRequired';
import { copyToClipboard } from '../helpers';

export default function CredentialViewPage() {
    const navigate = useNavigate();
    const { id } = useParams<{ id: string }>();
    const { sessionToken, verificationStatus } = useAppContext();

    const [showPassword, setShowPassword] = useState(false);
    const [showToast, setShowToast] = useState(false);

    const [getCredential, credential, getState, getError] = useApi(async (credId: number) => {
        const cred = await CredentialsService.getById(credId, sessionToken);
        return cred;
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

    const handleCopyPassword = async () => {
        if (credential?.password) {
            try {
                await copyToClipboard(credential.password);
                setShowToast(true);
            } catch (err) {
                console.error('Failed to copy password:', err);
            }
        }
    };

    const handleCopyUsername = async () => {
        if (credential?.username) {
            try {
                await copyToClipboard(credential.username);
                setShowToast(true);
            } catch (err) {
                console.error('Failed to copy username:', err);
            }
        }
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
            <ApiErrorFallback api_error={getError} />

            <Breadcrumb
                items={[
                    { label: 'Credentials', href: '/credentials' },
                    { label: credential?.service_name || 'Loading...', active: true },
                ]}
            />

            <MasterPasswordRequired>
                <ApiSuspense api_state={getState} suspense={LoadingSuspense}>
                    <Row className="mb-4">
                        <Col>
                            <div className="d-flex justify-content-between align-items-center">
                                <h2>View Credential</h2>
                                {credential && (
                                    <Button variant="primary" onClick={() => navigate(`/credentials/${credential.id}/edit`)}>
                                        <Pencil className="me-2" />
                                        Edit
                                    </Button>
                                )}
                            </div>
                        </Col>
                    </Row>

                    {credential && (
                        <Row className="justify-content-center">
                            <Col md={12}>
                                <Card>
                                    <Card.Body>
                                        {credential.category && (
                                            <div className="mb-4">
                                                <h5 className="text-muted mb-2">Category</h5>
                                                <div className="p-3 bg-light rounded">
                                                    <span className="badge bg-secondary">{credential.category}</span>
                                                </div>
                                            </div>
                                        )}

                                        <div className="mb-4">
                                            <h5 className="text-muted mb-2">Service Name</h5>
                                            <div className="p-3 bg-light rounded">
                                                <strong>{credential.service_name}</strong>
                                            </div>
                                        </div>

                                        {credential.service_url && (
                                            <div className="mb-4">
                                                <h5 className="text-muted mb-2">Service URL</h5>
                                                <div className="p-3 bg-light rounded">
                                                    <a href={credential.service_url} target="_blank" rel="noopener noreferrer" className="text-decoration-none">
                                                        {credential.service_url}
                                                    </a>
                                                </div>
                                            </div>
                                        )}

                                        <div className="mb-4">
                                            <h5 className="text-muted mb-2">Username</h5>
                                            <div className="p-3 bg-light rounded d-flex justify-content-between align-items-center">
                                                <span className="font-monospace">{credential.username}</span>
                                                <Button variant="outline-secondary" size="sm" onClick={handleCopyUsername} title="Copy username">
                                                    <Clipboard />
                                                </Button>
                                            </div>
                                        </div>

                                        <div className="mb-4">
                                            <h5 className="text-muted mb-2">Password</h5>
                                            <div className="p-3 bg-light rounded d-flex justify-content-between align-items-center">
                                                <span className="font-monospace me-3">{showPassword ? credential.password : '••••••••••••••••'}</span>
                                                <div className="d-flex gap-2">
                                                    <Button
                                                        variant="outline-secondary"
                                                        size="sm"
                                                        onClick={() => setShowPassword(!showPassword)}
                                                        title={showPassword ? 'Hide password' : 'Show password'}
                                                    >
                                                        {showPassword ? <EyeSlash /> : <Eye />}
                                                    </Button>
                                                    <Button variant="outline-secondary" size="sm" onClick={handleCopyPassword} title="Copy password">
                                                        <Clipboard />
                                                    </Button>
                                                </div>
                                            </div>
                                        </div>

                                        {credential.notes && (
                                            <div className="mb-4">
                                                <h5 className="text-muted mb-2">Notes</h5>
                                                <div className="p-3 bg-light rounded">
                                                    <pre className="font-monospace mb-0">{credential.notes}</pre>
                                                </div>
                                            </div>
                                        )}

                                        {(credential.created_at || credential.updated_at) && (
                                            <div className="mb-3">
                                                <small className="text-muted">
                                                    {credential.created_at && <div>Created: {new Date(credential.created_at).toLocaleString()}</div>}
                                                    {credential.updated_at && credential.updated_at !== credential.created_at && (
                                                        <div>Updated: {new Date(credential.updated_at).toLocaleString()}</div>
                                                    )}
                                                </small>
                                            </div>
                                        )}
                                    </Card.Body>
                                </Card>
                            </Col>
                        </Row>
                    )}

                    <Toast onClose={() => setShowToast(false)} show={showToast} delay={3000} autohide className="position-fixed bottom-0 end-0 m-3">
                        <Toast.Body className="d-flex align-items-center">
                            <CheckCircle className="text-success me-2" />
                            Copied to clipboard!
                        </Toast.Body>
                    </Toast>
                </ApiSuspense>
            </MasterPasswordRequired>
        </Container>
    );
}
