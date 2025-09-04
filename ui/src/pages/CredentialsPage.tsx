import React, { useState } from 'react';
import { Container, Table, Button, Form, Row, Col, Pagination, Spinner } from 'react-bootstrap';
import { useNavigate } from 'react-router-dom';
import { CredentialsService, CredentialData, AuditCredentialsRequest } from '../services/CredentialsService';
import { useApi, ApiErrorFallback, ApiSuspense, useDebouncedEffect, ApiState, useSessionStorage } from '../react-utilities';
import { DeleteConfirmationModal } from '../components/DeleteConfirmationModal';
import { ImportModal } from '../components/ImportModal';
import { ExportModal } from '../components/ExportModal';
import { MasterPasswordRequired } from '../components/MasterPasswordRequired';
import { Eye, EyeSlash, Pencil, Trash, Download, Upload, X, Clipboard, ArrowUpRight } from 'react-bootstrap-icons';
import { useAppContext } from '../AppContext';
import { UtilsService, ImportCredentialsRequest } from '../services/UtilsService';
import { copyToClipboard } from '../helpers';

const ITEMS_PER_PAGE = 15;

export default function CredentialsPage() {
    const navigate = useNavigate();
    const { masterPassword, verificationStatus } = useAppContext();
    const [sessionSearchTerm, setSessionSearchTerm] = useSessionStorage('search-term', '');
    const [sessionCurrentPage, setSessionCurrentPage] = useSessionStorage('current-page', 1);
    const [searchTerm, setSearchTerm] = useState(sessionSearchTerm);
    const [currentPage, setCurrentPage] = useState(sessionCurrentPage);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [credentialToDelete, setCredentialToDelete] = useState<CredentialData | undefined>();
    const [showImportModal, setShowImportModal] = useState(false);
    const [showExportModal, setShowExportModal] = useState(false);
    const [auditResults, setAuditResults] = useState<CredentialData[] | null>(null);
    const [isAuditMode, setIsAuditMode] = useState(false);
    const [showSearchTerm, setShowSearchTerm] = useState(false);

    const updateSessionSearchTerm = (term: string) => {
        setSessionSearchTerm(term);
        setSearchTerm(term);
    };
    const updateSessionCurrentPage = (page: number) => {
        setSessionCurrentPage(page);
        setCurrentPage(page);
    };

    // Load credentials
    const [loadCredentials, credentials, loadState, loadError] = useApi(async () => {
        const data = await CredentialsService.list();
        return data;
    });

    // Delete credential
    const [handleDelete, , deleteState, deleteError] = useApi(async (id: number) => {
        await CredentialsService.delete(id);
        loadCredentials(); // Reload the list
    });

    // Initial load and search debounce
    useDebouncedEffect(
        () => {
            if (loadState === ApiState.NotLoaded) {
                loadCredentials();
            }
        },
        [loadState],
        300
    );

    // Export credentials
    const [handleExport, , exportState, exportError] = useApi(async (exportPassword: string) => {
        const blob = await UtilsService.exportCredentials(masterPassword, exportPassword);

        // Create a download link
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'credentials_export.zip';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    });

    // Import credentials
    const [handleImport, , importState, importError] = useApi(async (data: ImportCredentialsRequest) => {
        await UtilsService.importCredentials({
            ...data,
            master_password: masterPassword,
        });
        loadCredentials(); // Reload the list
    });

    // Copy password to clipboard
    const [handleCopyPassword, , copyState, copyError] = useApi(async (credentialId: number) => {
        const password = await CredentialsService.getPassword(credentialId, masterPassword);
        await copyToClipboard(password);
    });

    // Audit passwords
    const [handleAudit, , auditState, auditError] = useApi(async (data: AuditCredentialsRequest) => {
        const results = await CredentialsService.auditPasswords(data);
        setAuditResults(results);
        setIsAuditMode(true);
        updateSessionCurrentPage(1); // Reset to first page
        return results;
    });

    const handleSearchTermChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        updateSessionSearchTerm(e.target.value);
        updateSessionCurrentPage(1);
        // Clear audit mode when user searches normally
        if (isAuditMode) {
            setIsAuditMode(false);
            setAuditResults(null);
            setShowSearchTerm(false);
        }
    };

    const handleClearSearch = () => {
        updateSessionSearchTerm('');
        updateSessionCurrentPage(1);
        // Clear audit mode when user clears search
        if (isAuditMode) {
            setIsAuditMode(false);
            setAuditResults(null);
            setShowSearchTerm(false);
        }
    };

    const handleAuditClick = () => {
        const searchTermForAudit = searchTerm.trim();
        if (searchTermForAudit) {
            handleAudit({
                master_password: masterPassword,
                search_term: searchTermForAudit,
            });
        }
    };

    // Navigation handlers
    const handleOpenCreate = () => {
        navigate('/credentials/new');
    };

    const handleOpenView = (credential: CredentialData) => {
        navigate(`/credentials/${credential.id}`);
    };

    const handleOpenEdit = (credential: CredentialData) => {
        navigate(`/credentials/${credential.id}/edit`);
    };

    // Handle search - use audit results if in audit mode, otherwise use regular search
    const displayCredentials = isAuditMode ? auditResults : credentials;
    const searchTermLower = searchTerm.toLowerCase();
    const filteredCredentials = isAuditMode
        ? auditResults // Show audit results as-is (already filtered by password content)
        : displayCredentials?.filter((cred) => JSON.stringify(cred).toLocaleLowerCase().includes(searchTermLower));

    // Handle pagination
    const totalPages = Math.ceil((filteredCredentials?.length ?? 0) / ITEMS_PER_PAGE);
    const paginatedCredentials = filteredCredentials?.slice((currentPage - 1) * ITEMS_PER_PAGE, currentPage * ITEMS_PER_PAGE);

    // Handle delete confirmation
    const handleDeleteClick = (credential: CredentialData) => {
        setCredentialToDelete(credential);
        setShowDeleteModal(true);
    };

    const handleDeleteConfirm = async () => {
        if (credentialToDelete) {
            await handleDelete(credentialToDelete.id);
            setShowDeleteModal(false);
            setCredentialToDelete(undefined);
        }
    };

    return (
        <Container>
            <ApiErrorFallback api_error={loadError || deleteError || exportError || importError || copyError || auditError} />

            <Row className="mb-4 align-items-center">
                <Col>
                    <h2 className="mb-0 text-nowrap">My Credentials</h2>
                </Col>
                <Col xs="auto" className="d-none d-xl-flex">
                    <ApiSuspense
                        api_states={[loadState, exportState]}
                        suspense={
                            <Button variant="outline-primary" disabled className="me-2">
                                <Spinner animation="border" size="sm" className="me-2" />
                                Exporting...
                            </Button>
                        }
                    >
                        <Button
                            variant="outline-primary"
                            onClick={() => setShowExportModal(true)}
                            disabled={!verificationStatus.verified || exportState === ApiState.Loading}
                            className="me-2"
                        >
                            <Download className="me-1" />
                            Export
                        </Button>
                    </ApiSuspense>
                    <ApiSuspense
                        api_states={[loadState, importState]}
                        suspense={
                            <Button variant="outline-primary" disabled>
                                <Spinner animation="border" size="sm" className="me-2" />
                                Importing...
                            </Button>
                        }
                    >
                        <Button variant="outline-primary" onClick={() => setShowImportModal(true)} disabled={!verificationStatus.verified || importState === ApiState.Loading}>
                            <Upload className="me-1" />
                            Import
                        </Button>
                    </ApiSuspense>
                </Col>
            </Row>

            <MasterPasswordRequired>
                {/* Search Bar */}
                <Row className="mb-4">
                    <Col md={12} className="d-flex gap-2 flex-wrap justify-content-between align-items-center">
                        <div className="position-relative flex-grow-1">
                            <Form.Control
                                type={isAuditMode && !showSearchTerm ? 'password' : 'text'}
                                placeholder="Search credentials or enter text to audit passwords..."
                                value={searchTerm}
                                onChange={handleSearchTermChange}
                            />
                            {isAuditMode && searchTerm && (
                                <Button
                                    variant="link"
                                    size="sm"
                                    onClick={() => setShowSearchTerm(!showSearchTerm)}
                                    className="position-absolute top-50 translate-middle-y text-muted"
                                    style={{ border: 'none', background: 'none', right: searchTerm ? '2.5rem' : '0.5rem' }}
                                    title={showSearchTerm ? 'Hide search term' : 'Show search term'}
                                >
                                    {showSearchTerm ? <EyeSlash size={16} /> : <Eye size={16} />}
                                </Button>
                            )}
                            {searchTerm && (
                                <Button
                                    variant="link"
                                    size="sm"
                                    onClick={handleClearSearch}
                                    className="position-absolute end-0 top-50 translate-middle-y pe-2 text-muted"
                                    style={{ border: 'none', background: 'none' }}
                                >
                                    <X size={16} />
                                </Button>
                            )}
                        </div>
                        <div className="d-flex gap-2">
                            <ApiSuspense
                                api_states={[auditState]}
                                suspense={
                                    <Button variant="outline-info" disabled>
                                        <Spinner animation="border" size="sm" className="me-2" />
                                        Auditing...
                                    </Button>
                                }
                            >
                                <Button
                                    variant="outline-info"
                                    onClick={handleAuditClick}
                                    disabled={!verificationStatus.verified || auditState === ApiState.Loading || !searchTerm.trim()}
                                    className="text-nowrap"
                                    title={!searchTerm.trim() ? 'Enter a search term to audit passwords' : 'Search for credentials containing this text in their passwords'}
                                >
                                    Audit Passwords
                                </Button>
                            </ApiSuspense>
                            <ApiSuspense
                                api_states={[loadState]}
                                suspense={
                                    <Button variant="primary" disabled>
                                        <Spinner animation="border" size="sm" className="me-2" />
                                        Loading...
                                    </Button>
                                }
                            >
                                <Button variant="outline-primary" onClick={handleOpenCreate} className="text-nowrap">
                                    New Credential
                                </Button>
                            </ApiSuspense>
                        </div>
                    </Col>
                </Row>

                {isAuditMode && auditResults && (
                    <div className="alert alert-info mb-3">
                        <strong>Password Audit Results:</strong> Found {auditResults.length} credential(s) with passwords containing your query
                        <Button
                            variant="link"
                            size="sm"
                            onClick={() => {
                                setIsAuditMode(false);
                                setAuditResults(null);
                                setShowSearchTerm(false);
                            }}
                            className="float-end text-decoration-none"
                        >
                            Clear Results
                        </Button>
                    </div>
                )}

                <ApiSuspense
                    api_states={[loadState]}
                    suspense={
                        <div className="text-center mt-4">
                            <Spinner animation="border" />
                            <p className="mt-2">Loading credentials...</p>
                        </div>
                    }
                >
                    {/* Credentials Table */}
                    <div className="table-responsive">
                        <Table striped hover>
                            <thead>
                                <tr>
                                    <th className="">Category</th>
                                    <th>Service</th>
                                    <th className="d-lg-table-cell d-none">Username</th>
                                    <th className="text-end">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {paginatedCredentials?.map((cred) => (
                                    <tr key={cred.id}>
                                        <td className="">{cred.category || '-'}</td>
                                        <td>{cred.service_name}</td>
                                        <td className="d-lg-table-cell d-none">{cred.username}</td>
                                        <td className="text-nowrap text-end">
                                            {cred.service_url && (
                                                <Button variant="outline-primary" size="sm" className="me-1" href={cred.service_url} target="_blank" rel="noopener noreferrer">
                                                    <ArrowUpRight />
                                                </Button>
                                            )}
                                            <ApiSuspense
                                                api_states={[copyState]}
                                                suspense={
                                                    <Button variant="outline-success" size="sm" className="me-1" disabled>
                                                        <Spinner animation="border" size="sm" />
                                                    </Button>
                                                }
                                            >
                                                <Button
                                                    variant="outline-success"
                                                    size="sm"
                                                    className="me-1"
                                                    onClick={() => handleCopyPassword(cred.id)}
                                                    title="Copy Password"
                                                    disabled={!verificationStatus.verified || copyState === ApiState.Loading}
                                                >
                                                    <Clipboard />
                                                </Button>
                                            </ApiSuspense>
                                            <ApiSuspense
                                                api_states={[loadState]}
                                                suspense={
                                                    <Button variant="outline-info" size="sm" className="me-1 d-none d-lg-inline" disabled>
                                                        <Spinner animation="border" size="sm" />
                                                    </Button>
                                                }
                                            >
                                                <Button variant="outline-info" size="sm" className="me-1 d-none d-lg-inline" onClick={() => handleOpenView(cred)} title="View">
                                                    <Eye />
                                                </Button>
                                            </ApiSuspense>
                                            <ApiSuspense
                                                api_states={[loadState]}
                                                suspense={
                                                    <Button variant="outline-primary" size="sm" className="me-1" disabled>
                                                        <Spinner animation="border" size="sm" />
                                                    </Button>
                                                }
                                            >
                                                <Button variant="outline-primary" size="sm" className="me-1" onClick={() => handleOpenEdit(cred)} title="Edit">
                                                    <Pencil />
                                                </Button>
                                            </ApiSuspense>
                                            <ApiSuspense
                                                api_states={[loadState, deleteState]}
                                                suspense={
                                                    <Button variant="outline-danger" size="sm" disabled className="d-none d-lg-inline">
                                                        <Spinner animation="border" size="sm" />
                                                    </Button>
                                                }
                                            >
                                                <Button
                                                    variant="outline-danger"
                                                    size="sm"
                                                    onClick={() => handleDeleteClick(cred)}
                                                    disabled={deleteState === ApiState.Loading}
                                                    title="Delete"
                                                    className="d-none d-lg-inline"
                                                >
                                                    <Trash />
                                                </Button>
                                            </ApiSuspense>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </Table>
                    </div>
                    {/* Pagination */}
                    {totalPages > 1 && (
                        <div className="d-flex justify-content-center mt-4">
                            <Pagination>
                                <Pagination.First onClick={() => updateSessionCurrentPage(1)} disabled={currentPage === 1} />
                                <Pagination.Prev onClick={() => updateSessionCurrentPage(Math.max(1, currentPage - 1))} disabled={currentPage === 1} />

                                {[...Array(totalPages)].map((_, idx) => {
                                    // Show current page and up to 3 pages before/after
                                    if (
                                        idx + 1 === currentPage || // Current page
                                        (idx + 1 >= currentPage - 3 && idx + 1 <= currentPage + 3) // 3 pages before/after
                                    ) {
                                        return (
                                            <Pagination.Item key={idx + 1} active={currentPage === idx + 1} onClick={() => updateSessionCurrentPage(idx + 1)}>
                                                {idx + 1}
                                            </Pagination.Item>
                                        );
                                    }
                                    return null;
                                })}

                                <Pagination.Next onClick={() => updateSessionCurrentPage(Math.min(totalPages, currentPage + 1))} disabled={currentPage === totalPages} />
                                <Pagination.Last onClick={() => updateSessionCurrentPage(totalPages)} disabled={currentPage === totalPages} />
                            </Pagination>
                        </div>
                    )}
                </ApiSuspense>
            </MasterPasswordRequired>

            {/* Delete Confirmation Modal */}
            {credentialToDelete && (
                <DeleteConfirmationModal
                    show={showDeleteModal}
                    onHide={() => {
                        setShowDeleteModal(false);
                        setCredentialToDelete(undefined);
                    }}
                    onConfirm={handleDeleteConfirm}
                    itemName={credentialToDelete.service_name}
                />
            )}

            {/* Import Modal */}
            <ImportModal show={showImportModal} onHide={() => setShowImportModal(false)} onImport={handleImport} />

            {/* Export Modal */}
            <ExportModal show={showExportModal} onHide={() => setShowExportModal(false)} onExport={handleExport} />
        </Container>
    );
}
