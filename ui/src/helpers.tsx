export const copyToClipboard = async (text: string): Promise<void> => {
    // Try modern clipboard API first
    if (navigator.clipboard && window.isSecureContext) {
        try {
            await navigator.clipboard.writeText(text);
            console.log('Text copied to clipboard');
            return;
        } catch (err) {
            console.warn('Clipboard API failed, falling back to legacy method:', err);
        }
    }

    // Fallback for older browsers or non-secure contexts
    try {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        console.log('Text copied to clipboard (fallback method)');
    } catch (err) {
        console.error('Failed to copy text:', err);
        throw new Error('Failed to copy text to clipboard');
    }
};