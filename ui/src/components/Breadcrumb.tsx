import { Breadcrumb as BootstrapBreadcrumb } from 'react-bootstrap';
import { useNavigate } from 'react-router-dom';

interface BreadcrumbItem {
    label: string;
    href?: string;
    active?: boolean;
}

interface BreadcrumbProps {
    items: BreadcrumbItem[];
}

export function Breadcrumb({ items }: BreadcrumbProps) {
    const navigate = useNavigate();

    const handleClick = (href: string) => {
        navigate(href);
    };

    return (
        <BootstrapBreadcrumb className="mb-3">
            {items.map((item, index) => (
                <BootstrapBreadcrumb.Item 
                    key={index}
                    active={item.active}
                    onClick={item.href && !item.active ? () => handleClick(item.href!) : undefined}
                    style={item.href && !item.active ? { cursor: 'pointer' } : {}}
                >
                    {item.label}
                </BootstrapBreadcrumb.Item>
            ))}
        </BootstrapBreadcrumb>
    );
}