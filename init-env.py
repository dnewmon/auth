#!/usr/bin/env python3
import os
import secrets
import string
from pathlib import Path


def generate_secret_key(length=32):
    """Generate a cryptographically secure random string."""
    alphabet = string.ascii_letters + string.digits  # + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))


def ensure_directory_exists(path):
    """Create directory if it doesn't exist."""
    Path(path).mkdir(parents=True, exist_ok=True)


def prompt_user(prompt, default=None, required=True):
    """Prompt user for input with optional default value."""
    if default:
        prompt = f"{prompt} [{default}]: "
    else:
        prompt = f"{prompt}: "

    while True:
        value = input(prompt).strip()
        if value:
            return value
        if default is not None:
            return default
        if not required:
            return None
        print("This field is required. Please provide a value.")


def main():
    print("Initializing environment configuration...")

    # Ensure the database directory exists
    ensure_directory_exists("db")

    # Read the example file
    try:
        with open(".env.example", "r") as f:
            example_content = f.read()
    except FileNotFoundError:
        print("Error: .env.example file not found!")
        return

    # Generate new configuration
    config = {}

    # Required configurations with defaults
    config["FLASK_ENV"] = prompt_user(
        "Enter Flask environment (development/production/testing)",
        default="development",
    )

    # Generate random secrets
    config["SECRET_KEY"] = generate_secret_key(32)
    config["JWT_SECRET_KEY"] = generate_secret_key(32)

    # Database configuration
    config["DATABASE_URL"] = prompt_user(
        "Enter database URL (e.g., mysql+pymysql://user:pass@localhost/db)",
        default="sqlite:///db/local.db",
    )

    # Optional email configuration
    config["MAIL_SERVER"] = prompt_user("Enter mail server", required=True)
    config["MAIL_PORT"] = prompt_user("Enter mail port", default="587", required=True)
    config["MAIL_USE_TLS"] = prompt_user(
        "Use TLS (Connect insecure, and upgrade the connection to TLS)? (true/false)",
        default="true",
        required=True,
    )
    config["MAIL_USE_SSL"] = prompt_user(
        "Use SSL (Connect securely at the start)? (true/false)",
        default="false",
        required=True,
    )
    config["MAIL_USERNAME"] = prompt_user("Enter mail username", required=True)
    config["MAIL_PASSWORD"] = prompt_user("Enter mail password", required=True)
    config["MAIL_DEFAULT_SENDER"] = prompt_user(
        "Enter default sender email", default="noreply@example.com", required=True
    )

    # Create new .env file
    print("\nGenerating .env file...")

    new_content = []
    for line in example_content.split("\n"):
        if line.startswith("#") or not line.strip():
            new_content.append(line)
            continue

        key = line.split("=")[0].strip()
        if key in config:
            new_content.append(f"{key}={config[key]}")
        else:
            # Keep commented out optional configurations as is
            new_content.append(f"# {line}")

    # Write the new configuration
    with open(".env", "w") as f:
        f.write("\n".join(new_content))

    print(
        "\nConfiguration complete! Your .env file has been created with the following:"
    )
    print("- Random secret keys have been generated")
    print("- Database configuration has been set")
    if "MAIL_SERVER" in config:
        print("- Email configuration has been set")
    print(
        "\nMake sure to review the .env file and adjust any additional settings as needed."
    )


if __name__ == "__main__":
    main()
