import { Container, Nav, Navbar, Spinner } from 'react-bootstrap';
import { Link, Outlet, useNavigate } from 'react-router-dom';
import { AppContextProvider, useAppContext } from '../AppContext';
import { AuthService } from '../services/AuthService';
import { ApiErrorFallback, ApiState, ApiSuspense, useApi, useDebouncedEffect } from '../react-utilities';

function LayoutContent() {
    const { username, setUsername } = useAppContext();
    const navigate = useNavigate();

    const [checkAuth, , authState, authError] = useApi(async () => {
        const response = await AuthService.getCurrentUser();
        if (response !== undefined) {
            setUsername(response.username);
        }
        else {
            navigate('/login');
        }
    });

    const [logout, , logoutState, logoutError] = useApi(async () => {
        await AuthService.logout();
        setUsername('');
        navigate('/login');
    });

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
                    <Navbar.Toggle aria-controls="basic-navbar-nav" />
                    <Navbar.Collapse id="basic-navbar-nav">
                        <Nav className="me-auto">
                            <Nav.Link as={Link} to="/">
                                Home
                            </Nav.Link>
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
