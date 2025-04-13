import { NavigateFunction, RouteObject, useNavigate, useParams } from 'react-router-dom';
import HomePage from './pages/HomePage';
import CredentialsPage from './pages/CredentialsPage';
import MfaManagement from './pages/MfaManagement';
import Layout from './components/Layout';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import ForgotPasswordPage from './pages/ForgotPasswordPage';
import ResetPasswordPage from './pages/ResetPasswordPage';
import AccountRecoveryPage from './pages/AccountRecoveryPage';

export const site_routes: RouteObject[] = [
    {
        element: <Layout />,
        index: false,
        children: [
            {
                path: '',
                element: <HomePage />,
            },
            {
                path: 'login',
                element: <LoginPage />,
            },
            {
                path: 'register',
                element: <RegisterPage />,
            },
            {
                path: 'credentials',
                element: <CredentialsPage />,
            },
            {
                path: 'account',
                element: <MfaManagement />,
            },
            {
                path: 'account/recovery',
                element: <AccountRecoveryPage />,
            },
            {
                path: 'forgot-password',
                element: <ForgotPasswordPage />,
            },
            {
                path: 'reset-password/:token',
                element: <ResetPasswordPage />,
            },
        ],
    },
];

export class SiteNavigator {
    navigate: NavigateFunction;
    params: any;

    constructor() {
        this.navigate = useNavigate();
        this.params = useParams();
    }

    go_home() {
        this.navigate(`/`);
    }

    go_credentials() {
        this.navigate(`/credentials`);
    }

    get_params() {
        return this.params;
    }
}
