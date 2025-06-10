"""Add performance indexes for optimization

Revision ID: add_performance_indexes
Revises: 
Create Date: 2024-01-15 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_performance_indexes'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """Add performance optimization indexes."""
    
    # Add email index to users table (if not already exists)
    try:
        op.create_index('idx_users_email', 'users', ['email'])
    except:
        # Index might already exist if unique constraint creates it
        pass
    
    # Add duplicate detection index to credentials table
    try:
        op.create_index('idx_duplicate_detection', 'credentials', ['user_id', 'service_name', 'username'])
    except:
        # Index might already exist
        pass


def downgrade():
    """Remove performance optimization indexes."""
    
    # Remove the indexes
    try:
        op.drop_index('idx_users_email', table_name='users')
    except:
        pass
    
    try:
        op.drop_index('idx_duplicate_detection', table_name='credentials')
    except:
        pass