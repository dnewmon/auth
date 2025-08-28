import React, { useState } from 'react';
import { Modal, Form, Button, Alert, InputGroup } from 'react-bootstrap';
import { Eye, EyeSlash } from 'react-bootstrap-icons';

interface ExportModalProps {
    show: boolean;
    onHide: () => void;
    onExport: (exportPassword: string) => Promise<void>;
}

export const ExportModal: React.FC<ExportModalProps> = ({ show, onHide, onExport }) => {
    const [exportPassword, setExportPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [exporting, setExporting] = useState(false);

    const handleReset = () => {
        setExportPassword('');
        setConfirmPassword('');
        setShowPassword(false);
        setShowConfirmPassword(false);
        setError(null);
        setExporting(false);
    };

    const handleHide = () => {
        handleReset();
        onHide();
    };

    const handleExport = async () => {
        setError(null);

        if (!exportPassword.trim()) {
            setError('Export password is required');
            return;
        }

        if (exportPassword !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        if (exportPassword.length < 8) {
            setError('Export password must be at least 8 characters long');
            return;
        }

        setExporting(true);
        try {
            await onExport(exportPassword);
            handleHide();
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to export credentials');
        } finally {
            setExporting(false);
        }
    };

    const handleKeyPress = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !exporting && exportPassword && confirmPassword) {
            e.preventDefault();
            handleExport();
        }
    };

    return (
        <Modal show={show} onHide={handleHide} centered>
            <Modal.Header closeButton>
                <Modal.Title>Export Credentials</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                {error && <Alert variant="danger">{error}</Alert>}
                
                <div className="mb-4">
                    <p className="text-muted">
                        Your credentials will be exported as an encrypted ZIP file. 
                        Choose a strong password to protect the export file.
                    </p>
                </div>

                <Form.Group className="mb-3">
                    <Form.Label>Export Password</Form.Label>
                    <InputGroup>
                        <Form.Control
                            type={showPassword ? 'text' : 'password'}
                            placeholder="Enter a strong password for the export file"
                            value={exportPassword}
                            onChange={(e) => setExportPassword(e.target.value)}
                            onKeyPress={handleKeyPress}
                            disabled={exporting}
                        />
                        <Button
                            variant="outline-secondary"
                            onClick={() => setShowPassword(!showPassword)}
                            disabled={exporting}
                            title={showPassword ? 'Hide password' : 'Show password'}
                        >
                            {showPassword ? <EyeSlash /> : <Eye />}
                        </Button>
                    </InputGroup>
                </Form.Group>

                <Form.Group className="mb-3">
                    <Form.Label>Confirm Export Password</Form.Label>
                    <InputGroup>
                        <Form.Control
                            type={showConfirmPassword ? 'text' : 'password'}
                            placeholder="Confirm the export password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            onKeyPress={handleKeyPress}
                            disabled={exporting}
                        />
                        <Button
                            variant="outline-secondary"
                            onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                            disabled={exporting}
                            title={showConfirmPassword ? 'Hide password' : 'Show password'}
                        >
                            {showConfirmPassword ? <EyeSlash /> : <Eye />}
                        </Button>
                    </InputGroup>
                </Form.Group>

                <div className="text-muted small">
                    <strong>Security Note:</strong> Use a strong, unique password that you'll remember. 
                    This password will be required to decrypt your exported credentials.
                </div>
            </Modal.Body>
            <Modal.Footer>
                <Button variant="secondary" onClick={handleHide} disabled={exporting}>
                    Cancel
                </Button>
                <Button 
                    variant="primary" 
                    onClick={handleExport} 
                    disabled={!exportPassword || !confirmPassword || exporting}
                >
                    {exporting ? 'Exporting...' : 'Export Credentials'}
                </Button>
            </Modal.Footer>
        </Modal>
    );
};