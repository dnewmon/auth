import React, { useState } from "react";
import { Modal, Form, Button, Row, Col, Alert } from "react-bootstrap";
import { Credential } from "../services/CredentialsService";
import { ImportCredentialsRequest } from "../services/UtilsService";

interface ImportModalProps {
    show: boolean;
    onHide: () => void;
    onImport: (data: ImportCredentialsRequest) => Promise<void>;
}

export const ImportModal: React.FC<ImportModalProps> = ({ show, onHide, onImport }) => {
    const [file, setFile] = useState<File | null>(null);
    const [fileContent, setFileContent] = useState<any[]>([]);
    const [fieldMapping, setFieldMapping] = useState<Record<string, string>>({});
    const [error, setError] = useState<string | null>(null);
    const [importing, setImporting] = useState(false);

    const credentialFields = ["service_name", "service_url", "username", "password", "category", "notes"];

    const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
        setError(null);
        if (!e.target.files || e.target.files.length === 0) return;

        const file = e.target.files[0];
        setFile(file);

        try {
            const content = await file.text();
            let parsedData: any[] = [];

            if (file.name.endsWith(".json")) {
                parsedData = JSON.parse(content);
            } else if (file.name.endsWith(".csv")) {
                const lines = content.split("\n");
                const headers = lines[0].split(",").map((h) => h.trim());
                parsedData = lines.slice(1).map((line) => {
                    const values = line.split(",").map((v) => v.trim());
                    return headers.reduce((obj, header, index) => {
                        obj[header] = values[index];
                        return obj;
                    }, {} as any);
                });
            } else {
                throw new Error("Unsupported file format. Please use JSON or CSV.");
            }

            setFileContent(parsedData);

            // Initialize field mapping with first row's fields
            if (parsedData.length > 0) {
                const availableFields = Object.keys(parsedData[0]);
                const initialMapping = credentialFields.reduce((acc, field) => {
                    const matchingField = availableFields.find((af) => af.toLowerCase().includes(field.toLowerCase()) || field.toLowerCase().includes(af.toLowerCase()));
                    if (matchingField) {
                        acc[matchingField] = field;
                    }
                    return acc;
                }, {} as Record<string, string>);
                setFieldMapping(initialMapping);
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : "Failed to parse file");
        }
    };

    const handleImport = async () => {
        if (!fileContent.length) {
            setError("No data to import");
            return;
        }

        setImporting(true);
        try {
            const credentials = fileContent.map((item) => {
                const credential: Partial<Credential> = {};
                Object.entries(fieldMapping).forEach(([sourceField, targetField]) => {
                    if (item[sourceField] !== undefined) {
                        (credential as any)[targetField] = item[sourceField];
                    }
                });
                return credential as Credential;
            });

            await onImport({
                credentials,
                master_password: "", // This will be filled by the parent component
            });
            onHide();
        } catch (err) {
            setError(err instanceof Error ? err.message : "Failed to import credentials");
        } finally {
            setImporting(false);
        }
    };

    return (
        <Modal show={show} onHide={onHide} size="lg">
            <Modal.Header closeButton>
                <Modal.Title>Import Credentials</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                {error && <Alert variant="danger">{error}</Alert>}

                <Form.Group className="mb-3">
                    <Form.Label>Select File (JSON or CSV)</Form.Label>
                    <Form.Control type="file" accept=".json,.csv" onChange={handleFileChange} />
                </Form.Group>

                {fileContent.length > 0 && (
                    <>
                        <h5>Field Mapping</h5>
                        <p>Map the fields from your file to credential fields:</p>
                        <Row className="mb-3">
                            <Col>
                                <strong>File Field</strong>
                            </Col>
                            <Col>
                                <strong>Credential Field</strong>
                            </Col>
                        </Row>
                        {Object.keys(fileContent[0]).map((sourceField) => (
                            <Row key={sourceField} className="mb-2">
                                <Col>{sourceField}</Col>
                                <Col>
                                    <Form.Select
                                        value={fieldMapping[sourceField] || ""}
                                        onChange={(e) => {
                                            setFieldMapping((prev) => ({
                                                ...prev,
                                                [sourceField]: e.target.value,
                                            }));
                                        }}
                                    >
                                        <option value="">-- Select Field --</option>
                                        {credentialFields.map((field) => (
                                            <option key={field} value={field}>
                                                {field}
                                            </option>
                                        ))}
                                    </Form.Select>
                                </Col>
                            </Row>
                        ))}
                    </>
                )}
            </Modal.Body>
            <Modal.Footer>
                <Button variant="secondary" onClick={onHide}>
                    Cancel
                </Button>
                <Button variant="primary" onClick={handleImport} disabled={!fileContent.length || importing}>
                    {importing ? "Importing..." : "Import"}
                </Button>
            </Modal.Footer>
        </Modal>
    );
};
