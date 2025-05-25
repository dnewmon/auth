"""
Dummy tests to verify the testing infrastructure is working correctly.
"""
import pytest
import sys
from pathlib import Path


class TestBasicFunctionality:
    """Test basic Python functionality to verify testing framework."""
    
    def test_basic_math(self):
        """Test basic mathematical operations."""
        assert 2 + 2 == 4
        assert 10 - 5 == 5
        assert 3 * 4 == 12
        assert 8 / 2 == 4
    
    def test_string_operations(self):
        """Test string operations."""
        test_string = "Signa4"
        assert len(test_string) == 6
        assert test_string.lower() == "signa4"
        assert test_string.upper() == "SIGNA4"
        assert "Sign" in test_string
    
    def test_list_operations(self):
        """Test list operations."""
        test_list = [1, 2, 3, 4, 5]
        assert len(test_list) == 5
        assert test_list[0] == 1
        assert test_list[-1] == 5
        assert sum(test_list) == 15
        
        test_list.append(6)
        assert len(test_list) == 6
        assert test_list[-1] == 6


class TestFixtures:
    """Test the custom fixtures defined in conftest.py."""
    
    def test_sample_data_fixture(self, sample_data):
        """Test that the sample_data fixture works correctly."""
        assert sample_data["test_string"] == "Hello, World!"
        assert sample_data["test_number"] == 42
        assert len(sample_data["test_list"]) == 5
        assert sample_data["test_dict"]["key1"] == "value1"
    
    def test_mock_environment_fixture(self, mock_environment):
        """Test that the mock_environment fixture works correctly."""
        import os
        assert os.environ.get("TESTING") == "true"
        assert os.environ.get("FLASK_ENV") == "testing"


class TestEnvironmentSetup:
    """Test that the testing environment is properly configured."""
    
    def test_python_path_configuration(self):
        """Test that the backend directory is in the Python path."""
        backend_path = str(Path(__file__).parent.parent / "backend")
        assert backend_path in sys.path
    
    def test_signa4_import(self):
        """Test that we can import signa4 modules."""
        try:
            import signa4
            # If we get here, the import was successful
            assert True
        except ImportError as e:
            # If import fails, let's check if the module structure exists
            backend_path = Path(__file__).parent.parent / "backend" / "signa4"
            if backend_path.exists():
                pytest.fail(f"signa4 module directory exists but import failed: {e}")
            else:
                pytest.skip("signa4 module directory does not exist yet")
    
    def test_pytest_working(self):
        """Test that pytest itself is working correctly."""
        assert pytest.__version__ is not None
        assert hasattr(pytest, "fixture")
        assert hasattr(pytest, "mark")


class TestAdvancedFeatures:
    """Test more advanced pytest features."""
    
    @pytest.mark.parametrize("input,expected", [
        (1, 2),
        (2, 4), 
        (3, 6),
        (4, 8),
    ])
    def test_parametrized_double(self, input, expected):
        """Test parametrized test case for doubling numbers."""
        assert input * 2 == expected
    
    def test_with_assertion_error(self):
        """Test that assertions work properly."""
        with pytest.raises(AssertionError):
            assert False, "This should raise an AssertionError"
    
    def test_with_exception(self):
        """Test exception handling."""
        with pytest.raises(ZeroDivisionError):
            result = 1 / 0