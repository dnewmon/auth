import { Modal, Button } from 'react-bootstrap';
import { Trash } from 'react-bootstrap-icons';

interface DeleteConfirmationModalProps {
    show: boolean;
    onHide: () => void;
    onConfirm: () => void;
    itemName: string;
}

export function DeleteConfirmationModal({ show, onHide, onConfirm, itemName }: DeleteConfirmationModalProps) {
    return (
        <Modal show={show} onHide={onHide} centered>
            <Modal.Header closeButton>
                <Modal.Title>
                    <Trash className="me-2" />
                    Confirm Deletion
                </Modal.Title>
            </Modal.Header>
            <Modal.Body>
                Are you sure you want to delete <strong>{itemName}</strong>? This action cannot be undone.
            </Modal.Body>
            <Modal.Footer>
                <Button variant="secondary" onClick={onHide}>
                    Cancel
                </Button>
                <Button variant="danger" onClick={onConfirm}>
                    Delete
                </Button>
            </Modal.Footer>
        </Modal>
    );
}
