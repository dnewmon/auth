# Performance Optimization Guide

This document outlines the performance optimizations implemented in the authentication system and provides guidance for maintaining optimal performance.

## Database Indexes

### Implemented Indexes

#### Users Table
- `username` - Index for username lookups during authentication
- `email` - Index for email-based user lookups and password reset flows

#### Credentials Table
- `user_id` - Index for user's credential queries
- `category` - Index for category-based filtering
- `created_at` - Index for temporal queries
- `updated_at` - Index for recently updated credentials
- `idx_user_category` - Composite index for user + category queries
- `idx_user_service` - Composite index for user + service name queries
- `idx_user_created` - Composite index for user + creation time queries
- `idx_duplicate_detection` - Composite index for duplicate detection (user_id, service_name, username)

#### Audit Logs Table
- `event_type` - Index for filtering by event type
- `severity` - Index for filtering by severity level
- `user_id` - Index for user-specific audit logs
- `ip_address` - Index for IP-based security analysis
- `created_at` - Index for temporal audit queries
- `idx_audit_user_event` - Composite index for user + event type queries
- `idx_audit_time_severity` - Composite index for time + severity queries
- `idx_audit_ip_time` - Composite index for IP + time security analysis

#### Shared Credentials Table
- `credential_id` - Index for credential sharing queries
- `owner_id` - Index for owner-based sharing queries
- `recipient_id` - Index for recipient-based sharing queries
- `created_at` - Index for temporal sharing queries
- `idx_owner_recipient` - Composite index for owner + recipient queries
- `idx_recipient_status` - Composite index for recipient + status queries
- `idx_credential_recipient` - Composite index for credential + recipient queries

#### Token Tables (Password Reset, Email Verification, MFA)
- `user_id` - Index for user-specific token queries
- `token_hash` - Index for token lookup and validation

### Query Optimizations

#### N+1 Query Prevention

The following functions have been optimized to prevent N+1 queries using SQLAlchemy's `joinedload()`:

##### Shared Credentials Queries

**Before:**
```python
shares = SharedCredential.query.filter_by(recipient_id=current_user.id).all()
for share in shares:
    credential_name = share.credential.service_name  # N+1 query
    owner_name = share.owner.username  # N+1 query
```

**After:**
```python
shares = SharedCredential.query.filter_by(
    recipient_id=current_user.id
).options(
    joinedload(SharedCredential.credential),
    joinedload(SharedCredential.owner)
).all()
```

##### Recovery Key Counting

**Before:**
```python
has_recovery_keys = len(user.recovery_keys) > 0  # Loads all recovery keys
unused_keys = sum(1 for key in user.recovery_keys if not key.used_at)  # Iterates through all
```

**After:**
```python
total_keys = RecoveryKey.query.filter_by(user_id=user.id).count()
has_recovery_keys = total_keys > 0
unused_keys = RecoveryKey.query.filter_by(user_id=user.id, used_at=None).count()
```

## Performance Best Practices

### Database Queries

1. **Use Eager Loading**: Always use `joinedload()` or `selectinload()` when you know you'll need related objects
2. **Use count() for counting**: Use database `count()` instead of loading objects and using Python `len()`
3. **Filter early**: Apply filters at the database level, not in Python
4. **Use appropriate indexes**: Ensure queries have supporting indexes for WHERE clauses

### Common Query Patterns

#### Filtering Credentials
```python
# Good: Uses composite index
credentials = Credential.query.filter_by(
    user_id=current_user.id,
    category='work'
).all()

# Good: Uses date index
recent_credentials = Credential.query.filter(
    Credential.user_id == current_user.id,
    Credential.created_at >= last_week
).all()
```

#### Counting Relationships
```python
# Good: Database count
credential_count = Credential.query.filter_by(user_id=user.id).count()

# Bad: Loading all objects
credential_count = len(user.credentials)
```

#### Complex Queries with Joins
```python
# Good: Single query with eager loading
shares = SharedCredential.query.filter_by(
    recipient_id=current_user.id
).options(
    joinedload(SharedCredential.credential),
    joinedload(SharedCredential.owner)
).all()
```

### Audit Log Performance

The audit log system is designed for high-performance logging:

1. **Async logging**: Consider implementing async audit logging for high-traffic scenarios
2. **Partitioning**: For very large datasets, consider table partitioning by date
3. **Archiving**: Implement archiving for old audit logs to keep the main table performant

### Monitoring Query Performance

#### Using Flask-SQLAlchemy Events

```python
from sqlalchemy import event
from sqlalchemy.engine import Engine
import time

@event.listens_for(Engine, "before_cursor_execute")
def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    context._query_start_time = time.time()

@event.listens_for(Engine, "after_cursor_execute")
def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    total = time.time() - context._query_start_time
    if total > 0.5:  # Log slow queries
        logger.warning(f"Slow query: {total:.2f}s - {statement[:100]}...")
```

#### Database Analysis Tools

1. **SQLite**: Use `.explain query plan` for query analysis
2. **PostgreSQL**: Use `EXPLAIN ANALYZE` for detailed query analysis
3. **MySQL**: Use `EXPLAIN` for query execution plans

## Migration Strategy

When adding new indexes:

1. **Create migration file**: Always use Alembic migrations for index changes
2. **Test on production-like data**: Ensure indexes don't cause performance issues during creation
3. **Monitor after deployment**: Watch for improved query performance
4. **Consider maintenance**: Large indexes require more maintenance during writes

## Future Optimizations

### Potential Areas for Improvement

1. **Materialized Views**: For complex reporting queries
2. **Query Caching**: Redis-based query result caching
3. **Connection Pooling**: Optimize database connection management
4. **Background Jobs**: Move heavy operations to background tasks
5. **Database Sharding**: For very large scale deployments

### Monitoring and Alerts

Set up monitoring for:
- Query execution time
- Database connection pool usage
- Index usage statistics
- Lock contention
- Slow query logs

## Conclusion

These optimizations provide a solid foundation for performance at scale. Regular monitoring and profiling should guide future optimization efforts based on actual usage patterns and bottlenecks.