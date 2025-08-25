import React from 'react';
import { Container, Card, Row, Col } from 'react-bootstrap';
import { Lock } from 'react-bootstrap-icons';
import { useAppContext } from '../AppContext';

interface MasterPasswordRequiredProps {
    children: React.ReactNode;
}

export function MasterPasswordRequired({ children }: MasterPasswordRequiredProps) {
    const { verificationStatus } = useAppContext();

    if (!verificationStatus.verified) {
        return (
            <Container>
                <Row className="justify-content-center">
                    <Col md={8} lg={6}>
                        <Card className="text-center">
                            <Card.Body className="py-5">
                                <Lock size={48} className="text-warning mb-3" />
                                <h4 className="mb-3">Master Password Required</h4>
                                <p className="text-muted mb-4">
                                    You need to verify your master password to access this content. Click the verification button in the navigation bar to unlock your credentials.
                                </p>
                                <div className="text-muted">
                                    <small>
                                        <strong>Tip:</strong> Look for the "Locked" button in the top navigation
                                    </small>
                                </div>
                            </Card.Body>
                        </Card>
                    </Col>
                </Row>
            </Container>
        );
    }

    return <>{children}</>;
}
