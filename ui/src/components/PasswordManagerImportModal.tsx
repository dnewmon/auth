import React, { useState, useEffect } from 'react';
import { Modal, Form, Button, Alert, Card, Badge, Table, Spinner, Row, Col } from 'react-bootstrap';
import { UtilsService, ImportPreviewData, ImportPasswordManagerData } from '../services/UtilsService';
import { useApi, ApiState } from '../react-utilities';

interface PasswordManagerImportModalProps {
    show: boolean;
    onHide: () => void;
    onImportComplete: (result: ImportPasswordManagerData) => void;
    masterPassword: string;
}

export const PasswordManagerImportModal: React.FC<PasswordManagerImportModalProps> = ({
    show,
    onHide,
    onImportComplete,
    masterPassword
}) => {
    const [step, setStep] = useState<'select' | 'preview' | 'import' | 'complete'>('select');
    const [fileContent, setFileContent] = useState<string>('');
    const [selectedFormat, setSelectedFormat] = useState<string>('');
    const [skipDuplicates, setSkipDuplicates] = useState<boolean>(true);
    const [enforcePolicy, setEnforcePolicy] = useState<boolean>(false);
    const [error, setError] = useState<string | null>(null);
    const [previewData, setPreviewData] = useState<ImportPreviewData | null>(null);
    const [importResult, setImportResult] = useState<ImportPasswordManagerData | null>(null);

    // Load supported formats
    const [loadFormats, formats] = useApi(async () => {
        return await UtilsService.getImportFormats();
    });

    // Preview import
    const [previewImport, , previewState] = useApi(async (content: string, format?: string) => {
        const result = await UtilsService.previewPasswordManagerImport({ content, format });
        setPreviewData(result);
        setStep('preview');
        return result;
    });

    // Perform import
    const [performImport, , importState] = useApi(async () => {
        if (!fileContent) throw new Error('No content to import');
        
        const result = await UtilsService.importFromPasswordManager({
            content: fileContent,
            master_password: masterPassword,
            format: selectedFormat || undefined,
            skip_duplicates: skipDuplicates,
            enforce_policy: enforcePolicy
        });
        
        setImportResult(result);
        setStep('complete');
        onImportComplete(result);
        return result;
    });

    useEffect(() => {
        if (show) {
            loadFormats();
            setStep('select');
            setFileContent('');
            setSelectedFormat('');
            setError(null);
            setPreviewData(null);
            setImportResult(null);
        }
    }, [show, loadFormats]);

    const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
        setError(null);
        if (!e.target.files || e.target.files.length === 0) return;

        const file = e.target.files[0];
        try {
            const content = await file.text();
            setFileContent(content);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to read file');
        }
    };

    const handlePreview = async () => {
        if (!fileContent) {
            setError('Please select a file first');
            return;
        }

        try {
            await previewImport(fileContent, selectedFormat);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to preview import');
        }
    };

    const handleImport = async () => {
        try {
            await performImport();
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to import credentials');
        }
    };

    const handleClose = () => {
        setStep('select');
        setFileContent('');
        setSelectedFormat('');
        setError(null);
        setPreviewData(null);
        setImportResult(null);
        onHide();
    };

    const getSeverityVariant = (issues: string[]): string => {
        if (issues.some(issue => issue.toLowerCase().includes('weak password'))) return 'warning';
        if (issues.some(issue => issue.toLowerCase().includes('missing'))) return 'danger';
        return 'info';
    };

    return (
        <Modal show={show} onHide={handleClose} size="lg">
            <Modal.Header closeButton>
                <Modal.Title>Import from Password Manager</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                {error && <Alert variant="danger">{error}</Alert>}

                {step === 'select' && (
                    <div>
                        <h5>Step 1: Select Your Export File</h5>
                        <p>Export your passwords from your current password manager and select the file below.</p>

                        {formats && (
                            <Card className="mb-3">
                                <Card.Header>
                                    <strong>Supported Formats</strong>
                                </Card.Header>
                                <Card.Body>
                                    {formats.supported_formats.map(format => (
                                        <div key={format} className="mb-2">
                                            <Badge bg="secondary" className="me-2">{format}</Badge>
                                            {formats.format_descriptions[format]}
                                        </div>
                                    ))}
                                </Card.Body>
                            </Card>
                        )}

                        <Form.Group className="mb-3">
                            <Form.Label>Select Export File</Form.Label>
                            <Form.Control 
                                type="file" 
                                accept=".csv,.json,.xml" 
                                onChange={handleFileChange} 
                            />
                            <Form.Text className="text-muted">
                                Supports CSV, JSON, and XML files from popular password managers
                            </Form.Text>
                        </Form.Group>

                        <Form.Group className="mb-3">
                            <Form.Label>Format Override (Optional)</Form.Label>
                            <Form.Select 
                                value={selectedFormat} 
                                onChange={(e) => setSelectedFormat(e.target.value)}
                            >
                                <option value="">Auto-detect format</option>
                                {formats?.supported_formats.map(format => (
                                    <option key={format} value={format}>{format}</option>
                                ))}
                            </Form.Select>
                            <Form.Text className="text-muted">
                                Leave blank to automatically detect the format
                            </Form.Text>
                        </Form.Group>

                        <h6>Import Options</h6>
                        <Form.Check
                            type="checkbox"
                            id="skip-duplicates"
                            label="Skip duplicate credentials"
                            checked={skipDuplicates}
                            onChange={(e) => setSkipDuplicates(e.target.checked)}
                            className="mb-2"
                        />
                        <Form.Check
                            type="checkbox"
                            id="enforce-policy"
                            label="Enforce password policy"
                            checked={enforcePolicy}
                            onChange={(e) => setEnforcePolicy(e.target.checked)}
                            className="mb-3"
                        />

                        <div className="d-flex justify-content-end">
                            <Button 
                                variant="primary" 
                                onClick={handlePreview}
                                disabled={!fileContent || previewState === ApiState.Loading}
                            >
                                {previewState === ApiState.Loading ? (
                                    <>
                                        <Spinner size="sm" className="me-2" />
                                        Analyzing...
                                    </>
                                ) : (
                                    'Preview Import'
                                )}
                            </Button>
                        </div>
                    </div>
                )}

                {step === 'preview' && previewData && (
                    <div>
                        <h5>Step 2: Preview Import</h5>
                        
                        <Row className="mb-3">
                            <Col md={6}>
                                <Card>
                                    <Card.Body>
                                        <Card.Title className="h6">Detection Summary</Card.Title>
                                        <p><strong>Format:</strong> {previewData.detected_format}</p>
                                        <p><strong>Credentials:</strong> {previewData.credential_count}</p>
                                    </Card.Body>
                                </Card>
                            </Col>
                            <Col md={6}>
                                <Card>
                                    <Card.Body>
                                        <Card.Title className="h6">Validation Issues</Card.Title>
                                        <p><Badge bg={previewData.validation_issues.length > 0 ? 'warning' : 'success'}>
                                            {previewData.validation_issues.length} issues found
                                        </Badge></p>
                                    </Card.Body>
                                </Card>
                            </Col>
                        </Row>

                        {previewData.validation_issues.length > 0 && (
                            <Card className="mb-3">
                                <Card.Header>
                                    <strong>Validation Issues</strong>
                                </Card.Header>
                                <Card.Body>
                                    <Table striped size="sm">
                                        <thead>
                                            <tr>
                                                <th>Service</th>
                                                <th>Issues</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {previewData.validation_issues.map((issue, index) => (
                                                <tr key={index}>
                                                    <td>{issue.service_name}</td>
                                                    <td>
                                                        {issue.issues.map((issueText, idx) => (
                                                            <Badge 
                                                                key={idx} 
                                                                bg={getSeverityVariant(issue.issues)} 
                                                                className="me-1"
                                                            >
                                                                {issueText}
                                                            </Badge>
                                                        ))}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </Table>
                                </Card.Body>
                            </Card>
                        )}

                        <Card className="mb-3">
                            <Card.Header>
                                <strong>Preview of Credentials</strong>
                            </Card.Header>
                            <Card.Body>
                                <Table striped size="sm">
                                    <thead>
                                        <tr>
                                            <th>Service</th>
                                            <th>Username</th>
                                            <th>Category</th>
                                            <th>Has Password</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {previewData.credentials.slice(0, 10).map((cred, index) => (
                                            <tr key={index}>
                                                <td>{cred.service_name}</td>
                                                <td>{cred.username}</td>
                                                <td>{cred.category || 'imported'}</td>
                                                <td>
                                                    <Badge bg={cred.password ? 'success' : 'warning'}>
                                                        {cred.password ? 'Yes' : 'No'}
                                                    </Badge>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </Table>
                                {previewData.credentials.length > 10 && (
                                    <p className="text-muted">
                                        Showing first 10 credentials. {previewData.credentials.length - 10} more will be imported.
                                    </p>
                                )}
                            </Card.Body>
                        </Card>

                        <div className="d-flex justify-content-between">
                            <Button variant="secondary" onClick={() => setStep('select')}>
                                Back
                            </Button>
                            <Button 
                                variant="primary" 
                                onClick={handleImport}
                                disabled={importState === ApiState.Loading}
                            >
                                {importState === ApiState.Loading ? (
                                    <>
                                        <Spinner size="sm" className="me-2" />
                                        Importing...
                                    </>
                                ) : (
                                    'Import Credentials'
                                )}
                            </Button>
                        </div>
                    </div>
                )}

                {step === 'complete' && importResult && (
                    <div>
                        <h5>Import Complete!</h5>
                        
                        <Alert variant="success">
                            {importResult.message}
                        </Alert>

                        <Row className="mb-3">
                            <Col md={3}>
                                <Card className="text-center">
                                    <Card.Body>
                                        <h4 className="text-success">{importResult.imported_count}</h4>
                                        <small>Imported</small>
                                    </Card.Body>
                                </Card>
                            </Col>
                            <Col md={3}>
                                <Card className="text-center">
                                    <Card.Body>
                                        <h4 className="text-warning">{importResult.skipped_count}</h4>
                                        <small>Skipped</small>
                                    </Card.Body>
                                </Card>
                            </Col>
                            <Col md={3}>
                                <Card className="text-center">
                                    <Card.Body>
                                        <h4 className="text-danger">{importResult.error_count}</h4>
                                        <small>Errors</small>
                                    </Card.Body>
                                </Card>
                            </Col>
                            <Col md={3}>
                                <Card className="text-center">
                                    <Card.Body>
                                        <h6>{importResult.detected_format}</h6>
                                        <small>Format</small>
                                    </Card.Body>
                                </Card>
                            </Col>
                        </Row>

                        {importResult.policy_violations && importResult.policy_violations.length > 0 && (
                            <Card>
                                <Card.Header>
                                    <strong>Policy Violations</strong>
                                </Card.Header>
                                <Card.Body>
                                    <Table striped size="sm">
                                        <thead>
                                            <tr>
                                                <th>Service</th>
                                                <th>Username</th>
                                                <th>Issues</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {importResult.policy_violations.map((violation, index) => (
                                                <tr key={index}>
                                                    <td>{violation.service_name}</td>
                                                    <td>{violation.username}</td>
                                                    <td>
                                                        {violation.errors.map((error, idx) => (
                                                            <Badge key={idx} bg="danger" className="me-1">
                                                                {error}
                                                            </Badge>
                                                        ))}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </Table>
                                </Card.Body>
                            </Card>
                        )}
                    </div>
                )}
            </Modal.Body>
            <Modal.Footer>
                <Button variant="secondary" onClick={handleClose}>
                    {step === 'complete' ? 'Close' : 'Cancel'}
                </Button>
            </Modal.Footer>
        </Modal>
    );
};