"""
Unit tests for app.utils.email module.

Tests email sending functionality, async threading, and error handling.
"""

import pytest
import threading
import time
from unittest.mock import patch, Mock, MagicMock
from flask import Flask
from flask_mail import Message

# Import the email module functions
from app.utils.email import send_async_email, send_email


class TestSendAsyncEmail:
    """Tests for the send_async_email function."""

    def test_send_async_email_success(self):
        """Test successful email sending within app context."""
        # Create a mock Flask app
        mock_app = Mock()
        mock_app.app_context.return_value.__enter__ = Mock()
        mock_app.app_context.return_value.__exit__ = Mock(return_value=None)
        
        # Create a mock message
        mock_message = Mock(spec=Message)
        
        # Mock the mail instance
        with patch('app.utils.email.mail') as mock_mail:
            send_async_email(mock_app, mock_message)
            
            # Verify app context was used
            mock_app.app_context.assert_called_once()
            
            # Verify mail.send was called with the message
            mock_mail.send.assert_called_once_with(mock_message)

    def test_send_async_email_exception_handling(self):
        """Test error handling when email sending fails."""
        # Create a mock Flask app with logger
        mock_app = Mock()
        mock_app.app_context.return_value.__enter__ = Mock()
        mock_app.app_context.return_value.__exit__ = Mock(return_value=None)
        mock_logger = Mock()
        mock_app.logger = mock_logger
        
        # Create a mock message
        mock_message = Mock(spec=Message)
        
        # Mock mail.send to raise an exception
        with patch('app.utils.email.mail') as mock_mail:
            test_exception = Exception("SMTP connection failed")
            mock_mail.send.side_effect = test_exception
            
            # Call send_async_email
            send_async_email(mock_app, mock_message)
            
            # Verify the exception was logged
            mock_logger.error.assert_called_once_with(
                "Failed to send email: SMTP connection failed", 
                exc_info=True
            )

    def test_send_async_email_with_app_context_exception(self):
        """Test handling when app context setup fails."""
        # Create a mock Flask app that raises exception on context
        mock_app = Mock()
        mock_app.app_context.side_effect = RuntimeError("App context error")
        
        mock_message = Mock(spec=Message)
        
        # This should raise the app context exception
        with pytest.raises(RuntimeError, match="App context error"):
            send_async_email(mock_app, mock_message)


class TestSendEmail:
    """Tests for the send_email function."""

    @patch('app.utils.email.current_app')
    @patch('app.utils.email.Message')
    @patch('app.utils.email.Thread')
    def test_send_email_basic(self, mock_thread_class, mock_message_class, mock_current_app):
        """Test basic email sending functionality."""
        # Mock current_app
        mock_app = Mock()
        mock_app.config = {"MAIL_DEFAULT_SENDER": "noreply@example.com"}
        mock_current_app._get_current_object.return_value = mock_app
        
        # Mock Message creation
        mock_message = Mock(spec=Message)
        mock_message_class.return_value = mock_message
        
        # Mock Thread
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread
        
        # Call send_email
        to_email = "user@example.com"
        subject = "Test Subject"
        template = "<h1>Test Email</h1>"
        
        result = send_email(to_email, subject, template)
        
        # Verify Message was created correctly
        mock_message_class.assert_called_once_with(
            subject, 
            recipients=[to_email], 
            html=template, 
            sender="noreply@example.com"
        )
        
        # Verify Thread was created and started
        mock_thread_class.assert_called_once()
        call_args = mock_thread_class.call_args
        assert call_args[1]['target'] == send_async_email
        assert call_args[1]['args'] == [mock_app, mock_message]
        
        mock_thread.start.assert_called_once()
        
        # Verify the thread is returned
        assert result == mock_thread

    @patch('app.utils.email.current_app')
    @patch('app.utils.email.Message')
    @patch('app.utils.email.Thread')
    def test_send_email_with_different_recipients(self, mock_thread_class, mock_message_class, mock_current_app):
        """Test email sending with various recipient formats."""
        # Setup mocks
        mock_app = Mock()
        mock_app.config = {"MAIL_DEFAULT_SENDER": "admin@example.com"}
        mock_current_app._get_current_object.return_value = mock_app
        
        mock_message = Mock(spec=Message)
        mock_message_class.return_value = mock_message
        
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread
        
        # Test with email containing special characters
        special_email = "user+test@sub.example.com"
        send_email(special_email, "Test", "<p>Content</p>")
        
        # Verify Message was created with special email
        mock_message_class.assert_called_with(
            "Test", 
            recipients=[special_email], 
            html="<p>Content</p>", 
            sender="admin@example.com"
        )

    @patch('app.utils.email.current_app')
    @patch('app.utils.email.Message')
    @patch('app.utils.email.Thread')
    def test_send_email_thread_parameters(self, mock_thread_class, mock_message_class, mock_current_app):
        """Test that thread is created with correct parameters."""
        # Setup mocks
        mock_app = Mock()
        mock_app.config = {"MAIL_DEFAULT_SENDER": "test@example.com"}
        mock_current_app._get_current_object.return_value = mock_app
        
        mock_message = Mock(spec=Message)
        mock_message_class.return_value = mock_message
        
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread
        
        # Call send_email
        send_email("recipient@example.com", "Subject", "<html>Body</html>")
        
        # Verify Thread was called with correct target and args
        mock_thread_class.assert_called_once_with(
            target=send_async_email,
            args=[mock_app, mock_message]
        )

    @patch('app.utils.email.current_app')
    def test_send_email_missing_config(self, mock_current_app):
        """Test behavior when MAIL_DEFAULT_SENDER is missing from config."""
        # Mock current_app without MAIL_DEFAULT_SENDER
        mock_app = Mock()
        mock_app.config = {}  # Missing MAIL_DEFAULT_SENDER
        mock_current_app._get_current_object.return_value = mock_app
        
        # This should raise KeyError when accessing the missing config
        with pytest.raises(KeyError):
            send_email("user@example.com", "Test", "<p>Test</p>")

    @patch('app.utils.email.current_app')
    @patch('app.utils.email.Message')
    @patch('app.utils.email.Thread')
    def test_send_email_empty_template(self, mock_thread_class, mock_message_class, mock_current_app):
        """Test sending email with empty template."""
        # Setup mocks
        mock_app = Mock()
        mock_app.config = {"MAIL_DEFAULT_SENDER": "test@example.com"}
        mock_current_app._get_current_object.return_value = mock_app
        
        mock_message = Mock(spec=Message)
        mock_message_class.return_value = mock_message
        
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread
        
        # Send email with empty template
        send_email("user@example.com", "Empty Content", "")
        
        # Verify Message was created with empty html
        mock_message_class.assert_called_once_with(
            "Empty Content", 
            recipients=["user@example.com"], 
            html="", 
            sender="test@example.com"
        )

    @patch('app.utils.email.current_app')
    @patch('app.utils.email.Message')
    @patch('app.utils.email.Thread')
    def test_send_email_unicode_content(self, mock_thread_class, mock_message_class, mock_current_app):
        """Test sending email with unicode content."""
        # Setup mocks
        mock_app = Mock()
        mock_app.config = {"MAIL_DEFAULT_SENDER": "test@example.com"}
        mock_current_app._get_current_object.return_value = mock_app
        
        mock_message = Mock(spec=Message)
        mock_message_class.return_value = mock_message
        
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread
        
        # Send email with unicode content
        unicode_subject = "Test 🔐 Security Alert"
        unicode_template = "<h1>Welcome! 欢迎 مرحبا</h1>"
        
        send_email("user@example.com", unicode_subject, unicode_template)
        
        # Verify Message handles unicode correctly
        mock_message_class.assert_called_once_with(
            unicode_subject, 
            recipients=["user@example.com"], 
            html=unicode_template, 
            sender="test@example.com"
        )


class TestEmailIntegration:
    """Integration tests for email functionality."""

    @patch('app.utils.email.current_app')
    @patch('app.utils.email.mail')
    def test_complete_email_workflow(self, mock_mail, mock_current_app):
        """Test complete email sending workflow from start to finish."""
        # Setup realistic Flask app mock
        mock_app = Mock()
        mock_app.config = {"MAIL_DEFAULT_SENDER": "noreply@authapp.com"}
        mock_current_app._get_current_object.return_value = mock_app
        
        # Mock app context manager
        context_manager = Mock()
        context_manager.__enter__ = Mock(return_value=mock_app)
        context_manager.__exit__ = Mock(return_value=None)
        mock_app.app_context.return_value = context_manager
        
        # Call send_email and wait for thread to complete
        thread = send_email(
            "user@example.com", 
            "Password Reset", 
            "<p>Click here to reset your password</p>"
        )
        
        # Wait for thread to complete
        thread.join(timeout=1.0)
        
        # Verify mail.send was called (thread execution)
        assert mock_mail.send.called

    @patch('app.utils.email.current_app')
    @patch('app.utils.email.mail')
    def test_email_error_handling_integration(self, mock_mail, mock_current_app):
        """Test error handling in complete workflow."""
        # Setup mocks
        mock_app = Mock()
        mock_app.config = {"MAIL_DEFAULT_SENDER": "test@example.com"}
        mock_current_app._get_current_object.return_value = mock_app
        
        # Mock app context
        context_manager = Mock()
        context_manager.__enter__ = Mock(return_value=mock_app)
        context_manager.__exit__ = Mock(return_value=None)
        mock_app.app_context.return_value = context_manager
        
        # Mock logger
        mock_logger = Mock()
        mock_app.logger = mock_logger
        
        # Make mail.send raise an exception
        mock_mail.send.side_effect = Exception("SMTP server unavailable")
        
        # Send email
        thread = send_email("user@example.com", "Test", "<p>Test</p>")
        
        # Wait for thread to complete
        thread.join(timeout=1.0)
        
        # Verify error was logged
        mock_logger.error.assert_called_once()
        error_call = mock_logger.error.call_args
        assert "Failed to send email: SMTP server unavailable" in error_call[0][0]
        assert error_call[1]["exc_info"] == True

    def test_thread_isolation(self):
        """Test that email sending doesn't block main thread."""
        with patch('app.utils.email.current_app') as mock_current_app, \
             patch('app.utils.email.mail') as mock_mail:
            
            # Setup mocks
            mock_app = Mock()
            mock_app.config = {"MAIL_DEFAULT_SENDER": "test@example.com"}
            mock_current_app._get_current_object.return_value = mock_app
            
            # Mock app context
            context_manager = Mock()
            context_manager.__enter__ = Mock(return_value=mock_app)
            context_manager.__exit__ = Mock(return_value=None)
            mock_app.app_context.return_value = context_manager
            
            # Make mail.send take some time to simulate slow SMTP
            def slow_send(msg):
                time.sleep(0.1)  # 100ms delay
            
            mock_mail.send.side_effect = slow_send
            
            # Record start time
            start_time = time.time()
            
            # Send email
            thread = send_email("user@example.com", "Test", "<p>Test</p>")
            
            # Function should return immediately (non-blocking)
            elapsed = time.time() - start_time
            assert elapsed < 0.05  # Should return in less than 50ms
            
            # Thread should still be alive
            assert thread.is_alive()
            
            # Wait for thread to complete
            thread.join(timeout=0.5)
            assert not thread.is_alive()


class TestEmailErrorScenarios:
    """Tests for various error scenarios and edge cases."""

    @patch('app.utils.email.current_app')
    def test_current_app_unavailable(self, mock_current_app):
        """Test behavior when current_app is not available."""
        # Make _get_current_object raise an exception
        mock_current_app._get_current_object.side_effect = RuntimeError("No application context")
        
        # This should raise the runtime error
        with pytest.raises(RuntimeError, match="No application context"):
            send_email("user@example.com", "Test", "<p>Test</p>")

    @patch('app.utils.email.current_app')
    @patch('app.utils.email.Message')
    def test_message_creation_failure(self, mock_message_class, mock_current_app):
        """Test behavior when Message creation fails."""
        # Setup current_app mock
        mock_app = Mock()
        mock_app.config = {"MAIL_DEFAULT_SENDER": "test@example.com"}
        mock_current_app._get_current_object.return_value = mock_app
        
        # Make Message raise an exception
        mock_message_class.side_effect = ValueError("Invalid email format")
        
        # This should raise the ValueError
        with pytest.raises(ValueError, match="Invalid email format"):
            send_email("invalid-email", "Test", "<p>Test</p>")

    @patch('app.utils.email.current_app')
    @patch('app.utils.email.Message')
    @patch('app.utils.email.Thread')
    def test_thread_creation_failure(self, mock_thread_class, mock_message_class, mock_current_app):
        """Test behavior when Thread creation fails."""
        # Setup mocks
        mock_app = Mock()
        mock_app.config = {"MAIL_DEFAULT_SENDER": "test@example.com"}
        mock_current_app._get_current_object.return_value = mock_app
        
        mock_message = Mock(spec=Message)
        mock_message_class.return_value = mock_message
        
        # Make Thread creation fail
        mock_thread_class.side_effect = RuntimeError("Cannot create thread")
        
        # This should raise the RuntimeError
        with pytest.raises(RuntimeError, match="Cannot create thread"):
            send_email("user@example.com", "Test", "<p>Test</p>")

    def test_send_async_email_with_none_values(self):
        """Test send_async_email with None values."""
        # Test with None app
        with pytest.raises(AttributeError):
            send_async_email(None, Mock())
        
        # Test with None message
        mock_app = Mock()
        mock_app.app_context.return_value.__enter__ = Mock()
        mock_app.app_context.return_value.__exit__ = Mock(return_value=None)
        
        with patch('app.utils.email.mail') as mock_mail:
            # This should not raise an exception, mail.send should handle None
            send_async_email(mock_app, None)
            mock_mail.send.assert_called_once_with(None)