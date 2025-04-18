import React, { useState } from 'react';
import { Container, Table, Button, Form, Row, Col, Pagination, Spinner } from 'react-bootstrap';
import { CredentialsService, CredentialData, CredentialRequest, MasterVerificationData } from '../services/CredentialsService';
import { useApi, ApiErrorFallback, ApiSuspense, useDebouncedEffect, ApiState, useTimer } from '../react-utilities';
import { CredentialModal } from '../components/CredentialModal';
import { MasterPasswordModal } from '../components/MasterPasswordModal';
import { DeleteConfirmationModal } from '../components/DeleteConfirmationModal';
import { ImportModal } from '../components/ImportModal';
import { Lock, Unlock, Eye, Pencil, Trash, Download, Upload } from 'react-bootstrap-icons';
import { useAppContext } from '../AppContext';
import { UtilsService, ImportCredentialsRequest } from '../services/UtilsService';

const ITEMS_PER_PAGE = 15;

export default function CredentialsPage() {
    const { masterPassword, setMasterPassword, verificationStatus, setVerificationStatus } = useAppContext();
    const [searchTerm, setSearchTerm] = useState('');
    const [currentPage, setCurrentPage] = useState(1);
    const [showModal, setShowModal] = useState(false);
    const [modalMode, setModalMode] = useState<'create' | 'view' | 'edit'>('create');
    const [selectedCredential, setSelectedCredential] = useState<CredentialData | undefined>();
    const [showMasterPasswordModal, setShowMasterPasswordModal] = useState(false);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [credentialToDelete, setCredentialToDelete] = useState<CredentialData | undefined>();
    const [masterPasswordModalMode, setMasterPasswordModalMode] = useState<'verify' | 'export'>('verify');
    const [showImportModal, setShowImportModal] = useState(false);

    // Load credentials
    const [loadCredentials, credentials, loadState, loadError] = useApi(async () => {
        const data = await CredentialsService.list();
        return data;
    });

    // Check master password verification status
    const [checkVerificationStatus] = useApi(async () => {
        const status = await CredentialsService.getMasterVerificationStatus();
        setVerificationStatus({
            ...status,
            verified: status.verified && masterPassword.length > 0,
        });

        return status;
    });

    // Verify master password
    const [verifyMasterPassword] = useApi(async (password: string) => {
        await CredentialsService.verifyMasterPassword(password);
        setMasterPassword(password); // Store the master password
        checkVerificationStatus();
    });

    // Create credential
    const [handleCreate, , createState, createError] = useApi(async (data: CredentialRequest) => {
        await CredentialsService.create(data);
        loadCredentials(); // Reload the list
    });

    // Update credential
    const [handleUpdate, , updateState, updateError] = useApi(async (data: CredentialRequest) => {
        if (selectedCredential) {
            await CredentialsService.update(selectedCredential.id, data);
            loadCredentials(); // Reload the list
        }
    });

    // Delete credential
    const [handleDelete, , deleteState, deleteError] = useApi(async (id: number) => {
        await CredentialsService.delete(id);
        loadCredentials(); // Reload the list
    });

    // Get specific credential
    const [getCredential] = useApi(async (id: number) => {
        const credential = await CredentialsService.getById(id, masterPassword);
        setSelectedCredential(credential);
        setShowModal(true);
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

    // Check verification status periodically
    const [trigger_verification_timer, cancel_verification_timer] = useTimer();

    useDebouncedEffect(() => {
        // Initial check of verification status
        checkVerificationStatus();

        // Set up timer based on expiration
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

        // Update timer whenever verification status changes
        if (verificationStatus.expires_at) {
            setupExpirationTimer(verificationStatus);
        }

        return cancel_verification_timer;
    }, [verificationStatus.expires_at]);

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

    const handleSearchTermChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setSearchTerm(e.target.value);
        setCurrentPage(1);
    };

    // Modal handlers
    const handleOpenCreate = () => {
        if (!verificationStatus.verified) {
            setMasterPasswordModalMode('verify');
            setShowMasterPasswordModal(true);
            return;
        }
        setModalMode('create');
        setSelectedCredential(undefined);
        setShowModal(true);
    };

    const handleOpenView = (credential: CredentialData) => {
        if (!verificationStatus.verified) {
            setMasterPasswordModalMode('verify');
            setShowMasterPasswordModal(true);
            return;
        }
        setModalMode('view');
        getCredential(credential.id);
    };

    const handleOpenEdit = (credential: CredentialData) => {
        if (!verificationStatus.verified) {
            setMasterPasswordModalMode('verify');
            setShowMasterPasswordModal(true);
            return;
        }
        setModalMode('edit');
        getCredential(credential.id);
    };

    const handleCloseModal = () => {
        setShowModal(false);
        setSelectedCredential(undefined);
    };

    const handleSave = async (data: Omit<CredentialRequest, 'master_password'>) => {
        if (modalMode === 'create') {
            await handleCreate({
                ...data,
                master_password: masterPassword,
            });
        } else if (modalMode === 'edit' && selectedCredential) {
            await handleUpdate({
                ...data,
                master_password: masterPassword,
            });
        }
    };

    const handleExportClick = () => {
        setMasterPasswordModalMode('export');
        setShowMasterPasswordModal(true);
    };

    const handleMasterPasswordSubmit = async (password: string) => {
        if (masterPasswordModalMode === 'verify') {
            await verifyMasterPassword(password);
        } else {
            await handleExport(password);
        }
    };

    // Handle search
    const filteredCredentials = credentials?.filter(
        (cred) =>
            cred.service_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
            (cred.service_url && cred.service_url.toLowerCase().includes(searchTerm.toLowerCase())) ||
            (cred.category && cred.category.toLowerCase().includes(searchTerm.toLowerCase()))
    );

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
            <ApiErrorFallback api_error={loadError || deleteError || createError || updateError || exportError || importError} />

            <Row className="mb-4 align-items-center">
                <Col>
                    <h2 className="mb-0">My Credentials</h2>
                </Col>
                <Col xs="auto">
                    <ApiSuspense
                        api_states={[loadState]}
                        suspense={
                            <Button variant="warning" disabled>
                                <Spinner animation="border" size="sm" className="me-2" />
                                Loading...
                            </Button>
                        }
                    >
                        <Button
                            variant={verificationStatus.verified ? 'success' : 'warning'}
                            className="me-2"
                            onClick={() => {
                                setMasterPasswordModalMode('verify');
                                setShowMasterPasswordModal(true);
                            }}
                        >
                            {verificationStatus.verified ? <Unlock className="me-1" /> : <Lock className="me-1" />}
                            {verificationStatus.verified ? 'Unlocked' : 'Locked'}
                        </Button>
                    </ApiSuspense>
                    <ApiSuspense
                        api_states={[loadState, exportState]}
                        suspense={
                            <Button variant="outline-primary" disabled className="me-2">
                                <Spinner animation="border" size="sm" className="me-2" />
                                Exporting...
                            </Button>
                        }
                    >
                        <Button variant="outline-primary" onClick={handleExportClick} disabled={!verificationStatus.verified || exportState === ApiState.Loading} className="me-2">
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

            {/* Search Bar */}
            <Row className="mb-4">
                <Col md={6}>
                    <Form.Control type="text" placeholder="Search credentials..." value={searchTerm} onChange={handleSearchTermChange} />
                </Col>
                <Col md={6} className="text-end">
                    <ApiSuspense
                        api_states={[loadState]}
                        suspense={
                            <Button variant="primary" disabled>
                                <Spinner animation="border" size="sm" className="me-2" />
                                Loading...
                            </Button>
                        }
                    >
                        <Button variant="primary" onClick={handleOpenCreate}>
                            Add New Credential
                        </Button>
                    </ApiSuspense>
                </Col>
            </Row>

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
                                <th className="d-xl-table-cell d-none">Category</th>
                                <th>Service</th>
                                <th className="d-xl-table-cell d-none">URL</th>
                                <th className="d-md-table-cell d-none">Username</th>
                                <th className="text-end">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {paginatedCredentials?.map((cred) => (
                                <tr key={cred.id}>
                                    <td className="d-xl-table-cell d-none">{cred.category || '-'}</td>
                                    <td>{cred.service_name}</td>
                                    <td className="d-xl-table-cell d-none text-truncate">
                                        {cred.service_url && (
                                            <a href={cred.service_url} target="_blank" rel="noopener noreferrer">
                                                {cred.service_url}
                                            </a>
                                        )}
                                    </td>
                                    <td className="d-md-table-cell d-none">{cred.username}</td>
                                    <td className="text-nowrap text-end">
                                        <ApiSuspense
                                            api_states={[loadState]}
                                            suspense={
                                                <Button variant="outline-info" size="sm" className="me-2" disabled>
                                                    <Spinner animation="border" size="sm" />
                                                </Button>
                                            }
                                        >
                                            <Button
                                                variant="outline-info"
                                                size="sm"
                                                className="me-2"
                                                onClick={() => handleOpenView(cred)}
                                                title="View"
                                                disabled={!verificationStatus.verified}
                                            >
                                                <Eye />
                                            </Button>
                                        </ApiSuspense>
                                        <ApiSuspense
                                            api_states={[loadState]}
                                            suspense={
                                                <Button variant="outline-primary" size="sm" className="me-2" disabled>
                                                    <Spinner animation="border" size="sm" />
                                                </Button>
                                            }
                                        >
                                            <Button
                                                variant="outline-primary"
                                                size="sm"
                                                className="me-2"
                                                onClick={() => handleOpenEdit(cred)}
                                                title="Edit"
                                                disabled={!verificationStatus.verified}
                                            >
                                                <Pencil />
                                            </Button>
                                        </ApiSuspense>
                                        <ApiSuspense
                                            api_states={[loadState, deleteState]}
                                            suspense={
                                                <Button variant="outline-danger" size="sm" disabled>
                                                    <Spinner animation="border" size="sm" />
                                                </Button>
                                            }
                                        >
                                            <Button
                                                variant="outline-danger"
                                                size="sm"
                                                onClick={() => handleDeleteClick(cred)}
                                                disabled={!verificationStatus.verified || deleteState === ApiState.Loading}
                                                title="Delete"
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
                            <Pagination.First onClick={() => setCurrentPage(1)} disabled={currentPage === 1} />
                            <Pagination.Prev onClick={() => setCurrentPage((p) => Math.max(1, p - 1))} disabled={currentPage === 1} />

                            {[...Array(totalPages)].map((_, idx) => {
                                // Show current page and up to 3 pages before/after
                                if (
                                    idx + 1 === currentPage || // Current page
                                    (idx + 1 >= currentPage - 3 && idx + 1 <= currentPage + 3) // 3 pages before/after
                                ) {
                                    return (
                                        <Pagination.Item key={idx + 1} active={currentPage === idx + 1} onClick={() => setCurrentPage(idx + 1)}>
                                            {idx + 1}
                                        </Pagination.Item>
                                    );
                                }
                                return null;
                            })}

                            <Pagination.Next onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages} />
                            <Pagination.Last onClick={() => setCurrentPage(totalPages)} disabled={currentPage === totalPages} />
                        </Pagination>
                    </div>
                )}
            </ApiSuspense>

            {/* Credential Modal */}
            {showModal && (
                <CredentialModal
                    show={showModal}
                    onHide={handleCloseModal}
                    mode={modalMode}
                    credential={selectedCredential}
                    onSave={handleSave}
                    createState={createState}
                    updateState={updateState}
                    createError={createError}
                    updateError={updateError}
                />
            )}

            {/* Master Password Modal */}
            {showMasterPasswordModal && (
                <MasterPasswordModal
                    show={showMasterPasswordModal}
                    onHide={() => setShowMasterPasswordModal(false)}
                    onVerify={handleMasterPasswordSubmit}
                    mode={masterPasswordModalMode}
                />
            )}

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
        </Container>
    );
}
