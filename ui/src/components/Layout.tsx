import { Container, Nav, Navbar, Spinner, Button } from 'react-bootstrap';
import { Link, Outlet, useNavigate } from 'react-router-dom';
import { Lock, Unlock } from 'react-bootstrap-icons';
import { AppContextProvider, useAppContext } from '../AppContext';
import { AuthService } from '../services/AuthService';
import { CredentialsService, MasterVerificationData } from '../services/CredentialsService';
import { MasterPasswordModal } from './MasterPasswordModal';
import { ApiErrorFallback, ApiState, ApiSuspense, useApi, useDebouncedEffect, useTimer } from '../react-utilities';
import { useState } from 'react';

function LayoutContent() {
    const { username, setUsername, setSessionToken, verificationStatus, setVerificationStatus } = useAppContext();
    const navigate = useNavigate();
    const [showMasterPasswordModal, setShowMasterPasswordModal] = useState(false);

    const [checkAuth, , authState, authError] = useApi(async () => {
        const response = await AuthService.getCurrentUser();
        if (response !== undefined) {
            setUsername(response.username);
        } else {
            navigate('/login');
        }
    });

    const [logout, , logoutState, logoutError] = useApi(async () => {
        await AuthService.logout();
        setUsername('');
        navigate('/login');
    });

    // Check master password verification status
    const [checkVerificationStatus] = useApi(async () => {
        const status = await CredentialsService.getMasterVerificationStatus();
        setVerificationStatus(status);
        return status;
    });

    // Verify master password
    const [verifyMasterPassword] = useApi(async (password: string) => {
        const result = await CredentialsService.verifyMasterPassword(password);
        setSessionToken(result.session_token);
        checkVerificationStatus();
    });

    // Check verification status periodically
    const [trigger_verification_timer, cancel_verification_timer] = useTimer();

    useDebouncedEffect(() => {
        if (username) {
            checkVerificationStatus();

            const setupExpirationTimer = (status: MasterVerificationData) => {
                if (status.expires_at) {
                    const expiresAt = new Date(status.expires_at).getTime();
                    const now = new Date().getTime();
                    const timeUntilExpiry = Math.max(0, expiresAt - now);

                    if (timeUntilExpiry > 0) {
                        trigger_verification_timer(() => {
                            checkVerificationStatus();
                        }, timeUntilExpiry);
                    }
                }
            };

            if (verificationStatus.expires_at) {
                setupExpirationTimer(verificationStatus);
            }
        }

        return cancel_verification_timer;
    }, [username, verificationStatus.expires_at]);

    const handleMasterPasswordSubmit = async (password: string) => {
        await verifyMasterPassword(password);
    };

    useDebouncedEffect(() => {
        if (authState === ApiState.NotLoaded) {
            checkAuth();
        }
    }, [authState]);

    return (
        <>
            <Navbar bg="dark" variant="dark" expand="lg">
                <Container>
                    <Navbar.Brand as={Link} to="/">
                        Password Manager
                    </Navbar.Brand>
                    <Nav className="d-lg-none">
                        {username && (
                            <Button variant={verificationStatus.verified ? 'success' : 'warning'} size="sm" className="me-3" onClick={() => setShowMasterPasswordModal(true)}>
                                {verificationStatus.verified ? <Unlock className="me-1" /> : <Lock className="me-1" />}
                                {verificationStatus.verified ? 'Unlocked' : 'Locked'}
                            </Button>
                        )}
                    </Nav>
                    <Navbar.Toggle aria-controls="basic-navbar-nav" />
                    <Navbar.Collapse id="basic-navbar-nav">
                        <Nav className="me-auto">
                            {username && (
                                <>
                                    <Nav.Link as={Link} to="/credentials">
                                        Credentials
                                    </Nav.Link>
                                    <Nav.Link as={Link} to="/account">
                                        Account Settings
                                    </Nav.Link>
                                </>
                            )}
                        </Nav>
                        <Nav>
                            <div className="d-none d-lg-block mt-1">
                                {username && (
                                    <Button
                                        variant={verificationStatus.verified ? 'success' : 'warning'}
                                        size="sm"
                                        className="me-3"
                                        onClick={() => setShowMasterPasswordModal(true)}
                                    >
                                        {verificationStatus.verified ? <Unlock className="me-1" /> : <Lock className="me-1" />}
                                        {verificationStatus.verified ? 'Unlocked' : 'Locked'}
                                    </Button>
                                )}
                            </div>
                            {username ? (
                                <Nav.Link onClick={() => logout()}>Logout</Nav.Link>
                            ) : (
                                <Nav.Link as={Link} to="/login">
                                    Login
                                </Nav.Link>
                            )}
                        </Nav>
                    </Navbar.Collapse>
                </Container>
            </Navbar>
            <Container className="mt-4">
                {authError && authError.status !== 302 && authError.status !== 404 && <ApiErrorFallback api_error={authError} />}

                <ApiErrorFallback api_error={logoutError} />
                <ApiSuspense api_states={[authState, logoutState]} suspense={<Spinner />}>
                    <Outlet />
                </ApiSuspense>
            </Container>

            {/* Master Password Modal */}
            {showMasterPasswordModal && (
                <MasterPasswordModal show={showMasterPasswordModal} onHide={() => setShowMasterPasswordModal(false)} onVerify={handleMasterPasswordSubmit} mode="verify" />
            )}
        </>
    );
}

export default function Layout() {
    return (
        <AppContextProvider>
            <LayoutContent />
        </AppContextProvider>
    );
}
