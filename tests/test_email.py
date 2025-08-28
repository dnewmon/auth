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


class TestSendAsyncEmail:
    """Tests for the send_async_email function."""

    def test_send_async_email_success(self):
        """Test successful email sending within app context."""
        from app.utils.email import send_async_email
        
        # Create a mock Flask app
        mock_app = Mock()
        mock_app.app_context.return_value.__enter__ = Mock()
        mock_app.app_context.return_value.__exit__ = Mock(return_value=None)
        mock_app.logger = Mock()
        
        # Create a mock message with required attributes
        mock_message = Mock(spec=Message)
        mock_message.recipients = ['test@example.com']
        mock_message.sender = 'noreply@example.com'
        mock_message.subject = 'Test Subject'
        
        # Mock the mail instance
        with patch('app.utils.email.mail') as mock_mail:
            send_async_email(mock_app, mock_message)
            
            # Verify app context was used
            mock_app.app_context.assert_called_once()
            
            # Verify mail.send was called with the message
            mock_mail.send.assert_called_once_with(mock_message)

    def test_send_async_email_exception_handling(self):
        """Test error handling when email sending fails."""
        from app.utils.email import send_async_email
        
        # Create a mock Flask app with logger
        mock_app = Mock()
        mock_app.app_context.return_value.__enter__ = Mock()
        mock_app.app_context.return_value.__exit__ = Mock(return_value=None)
        mock_logger = Mock()
        mock_app.logger = mock_logger
        
        # Create a mock message with required attributes
        mock_message = Mock(spec=Message)
        mock_message.recipients = ['test@example.com']
        mock_message.sender = 'noreply@example.com'
        mock_message.subject = 'Test Subject'
        
        # Mock the mail instance to raise an exception
        with patch('app.utils.email.mail') as mock_mail:
            mock_mail.send.side_effect = Exception("Email sending failed")
            
            # This should not raise an exception
            send_async_email(mock_app, mock_message)
            
            # Verify that the exception was logged
            mock_logger.error.assert_called_once()
            error_call_args = mock_logger.error.call_args[0]
            assert "Failed to send email" in error_call_args[0]

    def test_send_async_email_app_context_exception(self):
        """Test error handling when app context setup fails."""
        from app.utils.email import send_async_email
        
        # Create a mock Flask app that raises an exception during context setup
        mock_app = Mock()
        mock_app.app_context.side_effect = Exception("Context setup failed")
        mock_logger = Mock()
        mock_app.logger = mock_logger
        
        # Create a mock message
        mock_message = Mock(spec=Message)
        
        # This should raise an exception since app context setup fails before error handling
        with pytest.raises(Exception, match="Context setup failed"):
            send_async_email(mock_app, mock_message)

    def test_send_async_email_with_unicode_content(self):
        """Test email sending with unicode content."""
        from app.utils.email import send_async_email
        
        # Create a mock Flask app
        mock_app = Mock()
        mock_app.app_context.return_value.__enter__ = Mock()
        mock_app.app_context.return_value.__exit__ = Mock(return_value=None)
        mock_app.logger = Mock()
        
        # Create a mock message with unicode content
        mock_message = Mock(spec=Message)
        mock_message.recipients = ['test@example.com']
        mock_message.sender = 'noreply@example.com'
        mock_message.subject = "Test Subject with émojis 🚀"
        mock_message.body = "Test body with unicode characters: café, naïve, résumé"
        
        # Mock the mail instance
        with patch('app.utils.email.mail') as mock_mail:
            send_async_email(mock_app, mock_message)
            
            # Verify mail.send was called
            mock_mail.send.assert_called_once_with(mock_message)


class TestSendEmail:
    """Tests for the main send_email function."""

    def test_send_email_success(self, app):
        """Test successful email sending with threading."""
        from app.utils.email import send_email
        
        with patch('app.utils.email.Thread') as mock_thread_class, \
             patch('app.utils.email.Message') as mock_message_class, \
             patch('app.utils.email.current_app', app):
            
            # Setup mocks
            mock_message = Mock(spec=Message)
            mock_message_class.return_value = mock_message
            
            mock_thread = Mock()
            mock_thread_class.return_value = mock_thread
            
            # Call send_email
            send_email(
                to="test@example.com",
                subject="Test Subject",
                template="<p>Test HTML content</p>",
                text_body="Test text content"
            )
            
            # Verify Message was created correctly
            mock_message_class.assert_called_once_with(
                subject="Test Subject",
                recipients=["test@example.com"],
                html="<p>Test HTML content</p>",
                body="Test text content"
            )
            
            # Verify Thread was created and started
            mock_thread_class.assert_called_once()
            mock_thread.start.assert_called_once()

    def test_send_email_minimal_parameters(self, app):
        """Test send_email with minimal required parameters."""
        from app.utils.email import send_email
        
        with patch('app.utils.email.Thread') as mock_thread_class, \
             patch('app.utils.email.Message') as mock_message_class, \
             patch('app.utils.email.current_app', app):
            
            mock_message = Mock(spec=Message)
            mock_message_class.return_value = mock_message
            
            mock_thread = Mock()
            mock_thread_class.return_value = mock_thread
            
            # Call with minimal parameters
            send_email(to="test@example.com", subject="Test")
            
            # Verify Message was created with minimal parameters
            mock_message_class.assert_called_once_with(
                subject="Test",
                recipients=["test@example.com"],
                html=None,
                body=None
            )

    def test_send_email_with_template_only(self, app):
        """Test send_email with HTML template only."""
        from app.utils.email import send_email
        
        with patch('app.utils.email.Thread') as mock_thread_class, \
             patch('app.utils.email.Message') as mock_message_class, \
             patch('app.utils.email.current_app', app):
            
            mock_message = Mock(spec=Message)
            mock_message_class.return_value = mock_message
            
            # Call with template only
            send_email(
                to="test@example.com",
                subject="Test",
                template="<h1>HTML Template</h1>"
            )
            
            # Verify Message was created correctly
            mock_message_class.assert_called_once_with(
                subject="Test",
                recipients=["test@example.com"],
                html="<h1>HTML Template</h1>",
                body=None
            )

    def test_send_email_with_text_body_only(self, app):
        """Test send_email with text body only."""
        from app.utils.email import send_email
        
        with patch('app.utils.email.Thread') as mock_thread_class, \
             patch('app.utils.email.Message') as mock_message_class, \
             patch('app.utils.email.current_app', app):
            
            mock_message = Mock(spec=Message)
            mock_message_class.return_value = mock_message
            
            # Call with text body only
            send_email(
                to="test@example.com",
                subject="Test",
                text_body="Plain text content"
            )
            
            # Verify Message was created correctly
            mock_message_class.assert_called_once_with(
                subject="Test",
                recipients=["test@example.com"],
                html=None,
                body="Plain text content"
            )

    def test_send_email_multiple_recipients(self, app):
        """Test send_email with multiple recipients."""
        from app.utils.email import send_email
        
        with patch('app.utils.email.Thread') as mock_thread_class, \
             patch('app.utils.email.Message') as mock_message_class, \
             patch('app.utils.email.current_app', app):
            
            mock_message = Mock(spec=Message)
            mock_message_class.return_value = mock_message
            
            # Test with string recipient (should be converted to list)
            send_email(
                to="test@example.com",
                subject="Test"
            )
            
            # Verify single recipient was converted to list
            mock_message_class.assert_called_with(
                subject="Test",
                recipients=["test@example.com"],
                html=None,
                body=None
            )

    def test_send_email_thread_configuration(self, app):
        """Test that email thread is configured correctly."""
        from app.utils.email import send_email
        
        with patch('app.utils.email.Thread') as mock_thread_class, \
             patch('app.utils.email.Message') as mock_message_class, \
             patch('app.utils.email.current_app', app):
            
            mock_message = Mock(spec=Message)
            mock_message_class.return_value = mock_message
            
            mock_thread = Mock()
            mock_thread_class.return_value = mock_thread
            
            send_email(to="test@example.com", subject="Test")
            
            # Verify Thread was configured correctly
            mock_thread_class.assert_called_once()
            thread_call_args = mock_thread_class.call_args
            
            # Check that target function is send_async_email
            assert thread_call_args[1]['target'].__name__ == 'send_async_email'
            
            # Check that args include app and message
            thread_args = thread_call_args[1]['args']
            assert len(thread_args) == 2
            assert thread_args[0] == app  # First arg should be the app
            assert thread_args[1] == mock_message  # Second arg should be the message

    def test_send_email_unicode_handling(self, app):
        """Test send_email with unicode characters."""
        from app.utils.email import send_email
        
        with patch('app.utils.email.Thread') as mock_thread_class, \
             patch('app.utils.email.Message') as mock_message_class, \
             patch('app.utils.email.current_app', app):
            
            mock_message = Mock(spec=Message)
            mock_message_class.return_value = mock_message
            
            # Test with unicode content
            send_email(
                to="test@example.com",
                subject="Test with émojis 🚀",
                template="<p>Café naïve résumé</p>",
                text_body="Plain text with unicode: café"
            )
            
            # Verify Message handles unicode correctly
            mock_message_class.assert_called_once_with(
                subject="Test with émojis 🚀",
                recipients=["test@example.com"],
                html="<p>Café naïve résumé</p>",
                body="Plain text with unicode: café"
            )


class TestEmailIntegration:
    """Integration tests for email functionality."""

    def test_email_function_isolation(self, app):
        """Test that email functions don't interfere with each other."""
        from app.utils.email import send_email
        
        with patch('app.utils.email.Thread') as mock_thread_class, \
             patch('app.utils.email.Message') as mock_message_class, \
             patch('app.utils.email.current_app', app):
            
            mock_thread_class.return_value = Mock()
            mock_message_class.return_value = Mock()
            
            # Send multiple emails
            send_email(to="test1@example.com", subject="Test 1")
            send_email(to="test2@example.com", subject="Test 2")
            
            # Verify both emails were processed independently
            assert mock_thread_class.call_count == 2
            assert mock_message_class.call_count == 2

    def test_email_with_app_context_integration(self, app):
        """Test email sending integrates properly with Flask app context."""
        from app.utils.email import send_email, send_async_email
        
        with patch('app.utils.email.mail') as mock_mail:
            # Test that send_async_email works with real app context
            with app.app_context():
                mock_message = Mock(spec=Message)
                mock_message.recipients = ['test@example.com']
                mock_message.sender = 'noreply@example.com'
                mock_message.subject = 'Test Subject'
                send_async_email(app, mock_message)
                
                # Verify mail.send was called
                mock_mail.send.assert_called_once_with(mock_message)

    def test_email_threading_behavior(self, app):
        """Test that email sending is truly non-blocking."""
        from app.utils.email import send_email
        
        with patch('app.utils.email.send_async_email') as mock_async_send, \
             patch('app.utils.email.Message') as mock_message_class, \
             patch('app.utils.email.current_app', app):
            
            # Use a real thread to test non-blocking behavior
            mock_message = Mock(spec=Message)
            mock_message_class.return_value = mock_message
            
            # Track if async function is called
            async_called = threading.Event()
            
            def mock_async_function(app_instance, message):
                time.sleep(0.1)  # Simulate email sending delay
                async_called.set()
            
            mock_async_send.side_effect = mock_async_function
            
            # Record start time
            start_time = time.time()
            
            # Send email
            send_email(to="test@example.com", subject="Test")
            
            # Function should return immediately (non-blocking)
            end_time = time.time()
            assert (end_time - start_time) < 0.05  # Should be very fast
            
            # Wait for async function to complete
            async_called.wait(timeout=1.0)
            assert async_called.is_set()


class TestEmailErrorScenarios:
    """Tests for email error scenarios and edge cases."""

    def test_send_email_with_empty_recipient(self, app):
        """Test send_email with empty recipient."""
        from app.utils.email import send_email
        
        with patch('app.utils.email.Thread') as mock_thread_class, \
             patch('app.utils.email.Message') as mock_message_class, \
             patch('app.utils.email.current_app', app):
            
            # Test with empty string recipient
            send_email(to="", subject="Test")
            
            # Should still create message (validation happens in Flask-Mail)
            mock_message_class.assert_called_once_with(
                subject="Test",
                recipients=[""],
                html=None,
                body=None
            )

    def test_send_email_with_none_subject(self, app):
        """Test send_email with None subject."""
        from app.utils.email import send_email
        
        with patch('app.utils.email.Thread') as mock_thread_class, \
             patch('app.utils.email.Message') as mock_message_class, \
             patch('app.utils.email.current_app', app):
            
            # Test with None subject
            send_email(to="test@example.com", subject=None)
            
            # Should pass None to Message
            mock_message_class.assert_called_once_with(
                subject=None,
                recipients=["test@example.com"],
                html=None,
                body=None
            )

    def test_send_async_email_mail_not_initialized(self):
        """Test send_async_email when mail is not properly initialized."""
        from app.utils.email import send_async_email
        
        mock_app = Mock()
        mock_app.app_context.return_value.__enter__ = Mock()
        mock_app.app_context.return_value.__exit__ = Mock(return_value=None)
        mock_logger = Mock()
        mock_app.logger = mock_logger
        
        mock_message = Mock(spec=Message)
        
        # Mock mail to raise AttributeError (not initialized)
        with patch('app.utils.email.mail') as mock_mail:
            mock_mail.send.side_effect = AttributeError("Mail not initialized")
            
            send_async_email(mock_app, mock_message)
            
            # Should log the error
            mock_logger.error.assert_called_once()

    def test_send_email_thread_creation_failure(self, app):
        """Test behavior when thread creation fails."""
        from app.utils.email import send_email
        
        with patch('app.utils.email.Thread') as mock_thread_class, \
             patch('app.utils.email.Message') as mock_message_class, \
             patch('app.utils.email.current_app', app):
            
            mock_message_class.return_value = Mock()
            mock_thread_class.side_effect = Exception("Thread creation failed")
            
            # Should raise the exception (not handled in send_email)
            with pytest.raises(Exception, match="Thread creation failed"):
                send_email(to="test@example.com", subject="Test")

    def test_send_email_message_creation_failure(self, app):
        """Test behavior when Message creation fails."""
        from app.utils.email import send_email
        
        with patch('app.utils.email.Message') as mock_message_class, \
             patch('app.utils.email.current_app', app):
            
            mock_message_class.side_effect = Exception("Message creation failed")
            
            # Should raise the exception (not handled in send_email)
            with pytest.raises(Exception, match="Message creation failed"):
                send_email(to="test@example.com", subject="Test")

    def test_send_async_email_logging_format(self):
        """Test that error logging in send_async_email includes proper details."""
        from app.utils.email import send_async_email
        
        mock_app = Mock()
        mock_app.app_context.return_value.__enter__ = Mock()
        mock_app.app_context.return_value.__exit__ = Mock(return_value=None)
        mock_logger = Mock()
        mock_app.logger = mock_logger
        
        mock_message = Mock(spec=Message)
        mock_message.subject = "Test Subject"
        mock_message.recipients = ["test@example.com"]
        
        # Mock mail to raise a specific exception
        with patch('app.utils.email.mail') as mock_mail:
            test_exception = Exception("Specific email error")
            mock_mail.send.side_effect = test_exception
            
            send_async_email(mock_app, mock_message)
            
            # Verify error was logged with exception details
            mock_logger.error.assert_called_once()
            log_call_args = mock_logger.error.call_args
            assert "Failed to send email" in log_call_args[0][0]
            assert log_call_args[1]['exc_info'] is True