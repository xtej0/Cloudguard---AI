# CloudGuard AI: Quick Implementation Guide (Phase 1 Code Scaffolds)

This document contains ready-to-use code scaffolds for Phase 1 implementation. Copy-paste these to accelerate development.

---

## 1. PROJECT STRUCTURE SETUP

```bash
# Create Phase 1 directory structure
mkdir -p backend/app/core
mkdir -p backend/app/auth/{models,routes,schemas}
mkdir -p backend/app/middleware
mkdir -p backend/tests/unit/auth
mkdir -p backend/tests/integration
mkdir -p backend/migrations/alembic/versions
mkdir -p scripts
mkdir -p k8s
mkdir -p .github/workflows
```

---

## 2. POSTGRESQL DATABASE SCHEMA

### `backend/migrations/versions/001_initial_schema.py` (Alembic migration)

```python
"""Initial schema with users, orgs, API keys."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

def upgrade():
    # Organizations
    op.create_table(
        'organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(100), nullable=False, unique=True),
        sa.Column('plan', sa.String(50), nullable=False, server_default='free'),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    
    # Users
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, primary_key=True),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email', sa.String(255), nullable=False, unique=True),
        sa.Column('password_hash', sa.String(255), nullable=True),
        sa.Column('oauth_provider', sa.String(50), nullable=True),
        sa.Column('oauth_id', sa.String(255), nullable=True),
        sa.Column('role', sa.String(50), nullable=False, server_default='analyst'),
        sa.Column('status', sa.String(50), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.UniqueConstraint('oauth_provider', 'oauth_id', name='uq_oauth'),
    )
    
    # API Keys
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, primary_key=True),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('key_hash', sa.String(255), nullable=False, unique=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('rate_limit_per_minute', sa.Integer, nullable=False, server_default='100'),
        sa.Column('rate_limit_per_month', sa.Integer, nullable=False, server_default='100000'),
        sa.Column('last_used_at', sa.DateTime, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime, nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
    )
    
    # Indices
    op.create_index('ix_users_org_id', 'users', ['org_id'])
    op.create_index('ix_api_keys_org_id', 'api_keys', ['org_id'])

def downgrade():
    op.drop_table('api_keys')
    op.drop_table('users')
    op.drop_table('organizations')
```

---

## 3. CORE DATABASE CONNECTION

### `backend/app/core/database.py`

```python
"""Database connection and session management."""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://cloudguard:password@localhost:5432/cloudguard"
)

engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=40,
    pool_pre_ping=True,  # Verify connections before using
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """FastAPI dependency for database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@contextmanager
def get_db_context():
    """Context manager for non-async code."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

---

## 4. SQLALCHEMY ORM MODELS

### `backend/app/auth/models.py`

```python
"""SQLAlchemy ORM models for users and organizations."""
from uuid import uuid4
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base
import enum

Base = declarative_base()

class RoleEnum(str, enum.Enum):
    ADMIN = "admin"
    SECURITY_LEAD = "security_lead"
    ANALYST = "analyst"
    VIEWER = "viewer"

class StatusEnum(str, enum.Enum):
    ACTIVE = "active"
    INVITED = "invited"
    SUSPENDED = "suspended"

class PlanEnum(str, enum.Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"

class Organization(Base):
    __tablename__ = "organizations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    plan = Column(SQLEnum(PlanEnum), nullable=False, default=PlanEnum.FREE)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Organization {self.name}>"

class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=True)
    oauth_provider = Column(String(50), nullable=True)  # 'google', 'github'
    oauth_id = Column(String(255), nullable=True)
    role = Column(SQLEnum(RoleEnum), nullable=False, default=RoleEnum.ANALYST)
    status = Column(SQLEnum(StatusEnum), nullable=False, default=StatusEnum.ACTIVE)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<User {self.email}>"

class ApiKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    key_hash = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    rate_limit_per_minute = Column(Integer, nullable=False, default=100)
    rate_limit_per_month = Column(Integer, nullable=False, default=100000)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
```

---

## 5. PYDANTIC SCHEMAS

### `backend/app/auth/schemas.py`

```python
"""Pydantic schemas for auth endpoints."""
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, validator

class UserBase(BaseModel):
    email: EmailStr
    role: str = Field(default="analyst")

class UserCreate(UserBase):
    password: str = Field(min_length=8)

class UserResponse(UserBase):
    id: UUID
    org_id: UUID
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class OrganizationBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)

class OrganizationCreate(OrganizationBase):
    pass

class OrganizationResponse(OrganizationBase):
    id: UUID
    plan: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    organization_name: str = Field(min_length=1, max_length=255)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: UserResponse
    organization: OrganizationResponse
```

---

## 6. JWT SECURITY UTILITIES

### `backend/app/core/security.py`

```python
"""JWT and security utilities."""
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class TokenData(BaseModel):
    user_id: str
    org_id: str
    role: str
    exp: datetime

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(
    user_id: str,
    org_id: str,
    role: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a JWT access token."""
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    expire = datetime.now(timezone.utc) + expires_delta
    payload = {
        "user_id": user_id,
        "org_id": org_id,
        "role": role,
        "exp": expire,
        "type": "access"
    }
    
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(user_id: str, org_id: str) -> str:
    """Create a JWT refresh token."""
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "user_id": user_id,
        "org_id": org_id,
        "exp": expire,
        "type": "refresh"
    }
    
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> Optional[TokenData]:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        org_id: str = payload.get("org_id")
        role: str = payload.get("role")
        
        if user_id is None or org_id is None:
            return None
        
        return TokenData(
            user_id=user_id,
            org_id=org_id,
            role=role,
            exp=datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc)
        )
    except JWTError:
        return None
```

---

## 7. AUTH SERVICE LAYER

### `backend/app/auth/service.py`

```python
"""Business logic for authentication."""
from uuid import UUID, uuid4
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.auth.models import User, Organization, RoleEnum, StatusEnum
from app.core.security import hash_password, verify_password, create_access_token, create_refresh_token
from fastapi import HTTPException

class UserAlreadyExistsError(Exception):
    pass

class InvalidCredentialsError(Exception):
    pass

class AuthService:
    def __init__(self, db: Session):
        self.db = db
    
    def register_user(
        self,
        email: str,
        password: str,
        organization_name: str
    ) -> tuple[User, Organization, str, str]:
        """Register a new user and organization."""
        # Check if user already exists
        existing_user = self.db.query(User).filter(User.email == email).first()
        if existing_user:
            raise UserAlreadyExistsError(f"User with email {email} already exists")
        
        # Create organization
        org_slug = organization_name.lower().replace(" ", "-")[:50]
        organization = Organization(
            id=uuid4(),
            name=organization_name,
            slug=org_slug,
            plan="free"
        )
        self.db.add(organization)
        self.db.flush()  # Get the org ID without committing
        
        # Create user (first user is admin)
        user = User(
            id=uuid4(),
            org_id=organization.id,
            email=email,
            password_hash=hash_password(password),
            role=RoleEnum.ADMIN,
            status=StatusEnum.ACTIVE
        )
        self.db.add(user)
        self.db.commit()
        
        # Create tokens
        access_token = create_access_token(
            user_id=str(user.id),
            org_id=str(organization.id),
            role=user.role.value
        )
        refresh_token = create_refresh_token(
            user_id=str(user.id),
            org_id=str(organization.id)
        )
        
        return user, organization, access_token, refresh_token
    
    def authenticate_user(self, email: str, password: str) -> tuple[User, Organization, str, str]:
        """Authenticate user with email and password."""
        user = self.db.query(User).filter(User.email == email).first()
        if not user or not verify_password(password, user.password_hash or ""):
            raise InvalidCredentialsError("Invalid email or password")
        
        organization = self.db.query(Organization).filter(Organization.id == user.org_id).first()
        if not organization:
            raise InvalidCredentialsError("Organization not found")
        
        # Create tokens
        access_token = create_access_token(
            user_id=str(user.id),
            org_id=str(organization.id),
            role=user.role.value
        )
        refresh_token = create_refresh_token(
            user_id=str(user.id),
            org_id=str(organization.id)
        )
        
        return user, organization, access_token, refresh_token
    
    def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        """Get user by ID."""
        return self.db.query(User).filter(User.id == user_id).first()
    
    def get_organization_by_id(self, org_id: UUID) -> Optional[Organization]:
        """Get organization by ID."""
        return self.db.query(Organization).filter(Organization.id == org_id).first()
```

---

## 8. AUTH ROUTES

### `backend/app/auth/routes.py`

```python
"""API routes for authentication."""
from uuid import UUID
from sqlalchemy.orm import Session
from fastapi import APIRouter, HTTPException, Depends, status
from app.auth.service import AuthService, UserAlreadyExistsError, InvalidCredentialsError
from app.auth.schemas import SignupRequest, LoginRequest, TokenResponse, UserResponse, OrganizationResponse
from app.core.database import get_db

router = APIRouter(prefix="/auth", tags=["authentication"])

@router.post("/register", response_model=TokenResponse, status_code=201)
def register(request: SignupRequest, db: Session = Depends(get_db)):
    """Register a new user and organization."""
    try:
        service = AuthService(db)
        user, org, access_token, refresh_token = service.register_user(
            email=request.email,
            password=request.password,
            organization_name=request.organization_name
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=3600,
            user=UserResponse.from_orm(user),
            organization=OrganizationResponse.from_orm(org)
        )
    except UserAlreadyExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate user and return tokens."""
    try:
        service = AuthService(db)
        user, org, access_token, refresh_token = service.authenticate_user(
            email=request.email,
            password=request.password
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=3600,
            user=UserResponse.from_orm(user),
            organization=OrganizationResponse.from_orm(org)
        )
    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )
```

---

## 9. AUTH DEPENDENCIES

### `backend/app/auth/dependencies.py`

```python
"""FastAPI dependency for JWT verification."""
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthCredentials
from sqlalchemy.orm import Session
from app.core.security import verify_token, TokenData
from app.core.database import get_db
from app.auth.models import User
from uuid import UUID

security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Extract and verify JWT token from Authorization header."""
    token = credentials.credentials
    
    token_data = verify_token(token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = db.query(User).filter(User.id == UUID(token_data.user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user

async def get_current_org_id(
    current_user: User = Depends(get_current_user)
) -> UUID:
    """Get organization ID from current user."""
    return current_user.org_id
```

---

## 10. AUTH MIDDLEWARE

### `backend/app/middleware/auth.py`

```python
"""Middleware to add user context to all requests."""
from fastapi import Request, HTTPException, status
from fastapi.security import HTTPAuthCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.security import verify_token

security = HTTPBearer()

class AuthMiddleware(BaseHTTPMiddleware):
    """Verify JWT token on all protected routes."""
    
    async def dispatch(self, request: Request, call_next):
        # Skip auth for public endpoints
        if request.url.path in [
            "/auth/login",
            "/auth/register",
            "/health",
            "/docs",
            "/openapi.json"
        ]:
            return await call_next(request)
        
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header"
            )
        
        try:
            scheme, token = auth_header.split()
            if scheme.lower() != "bearer":
                raise ValueError
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format"
            )
        
        # Verify token
        token_data = verify_token(token)
        if not token_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Add token data to request state
        request.state.user_id = token_data.user_id
        request.state.org_id = token_data.org_id
        request.state.role = token_data.role
        
        return await call_next(request)
```

---

## 11. REDIS CACHE SETUP

### `backend/app/core/cache.py`

```python
"""Redis caching utilities."""
import os
import json
from typing import Any, Optional, Callable
from functools import wraps
import redis

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True
)

def cache_decorator(ttl: int = 3600, key_prefix: str = ""):
    """Decorator to cache function results in Redis."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Build cache key from function name and arguments
            cache_key = f"{key_prefix}:{func.__name__}"
            for arg in args:
                if isinstance(arg, (str, int, float)):
                    cache_key += f":{arg}"
            for k, v in sorted(kwargs.items()):
                if isinstance(v, (str, int, float)):
                    cache_key += f":{k}={v}"
            
            # Try to get from cache
            cached_value = redis_client.get(cache_key)
            if cached_value:
                return json.loads(cached_value)
            
            # Call function and cache result
            result = func(*args, **kwargs)
            redis_client.setex(
                cache_key,
                ttl,
                json.dumps(result, default=str)
            )
            
            return result
        return wrapper
    return decorator

def set_cache(key: str, value: Any, ttl: int = 3600):
    """Set a value in cache."""
    redis_client.setex(key, ttl, json.dumps(value, default=str))

def get_cache(key: str) -> Optional[Any]:
    """Get a value from cache."""
    value = redis_client.get(key)
    if value:
        return json.loads(value)
    return None

def delete_cache(key: str):
    """Delete a value from cache."""
    redis_client.delete(key)

def clear_cache_pattern(pattern: str):
    """Delete all keys matching a pattern."""
    for key in redis_client.scan_iter(match=pattern):
        redis_client.delete(key)
```

---

## 12. RATE LIMITING MIDDLEWARE

### `backend/app/middleware/rate_limit.py`

```python
"""Rate limiting middleware using Redis."""
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
import time
from app.core.cache import redis_client

# Rate limits per plan (requests per minute)
RATE_LIMITS = {
    "free": 100,
    "pro": 1000,
    "enterprise": 10000
}

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limit requests per organization and plan."""
    
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for public endpoints
        if request.url.path in ["/auth/login", "/auth/register", "/health"]:
            return await call_next(request)
        
        # Get org_id and role from request state
        org_id = getattr(request.state, "org_id", None)
        role = getattr(request.state, "role", None)
        
        if org_id is None:
            # If no auth context, skip rate limiting
            return await call_next(request)
        
        # Determine plan from role or org
        plan = self._get_plan_from_role(role)
        limit = RATE_LIMITS.get(plan, 100)
        
        # Create rate limit key (one per minute per org)
        current_minute = int(time.time() / 60)
        rate_limit_key = f"ratelimit:{org_id}:{current_minute}"
        
        # Increment counter
        count = redis_client.incr(rate_limit_key)
        redis_client.expire(rate_limit_key, 60)
        
        # Check limit
        if count > limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Limit: {limit} requests/minute"
            )
        
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - count))
        
        return response
    
    @staticmethod
    def _get_plan_from_role(role: str) -> str:
        """Determine plan tier based on user role."""
        # Simplified: in production, fetch from database
        if role == "admin":
            return "enterprise"
        elif role == "security_lead":
            return "pro"
        else:
            return "free"
```

---

## 13. DOCKER SETUP

### `backend/Dockerfile.prod`

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 cloudguard
USER cloudguard

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### `docker-compose.prod.yml`

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: cloudguard
      POSTGRES_USER: cloudguard
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cloudguard"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  neo4j:
    image: neo4j:5.13-enterprise
    environment:
      NEO4J_AUTH: ${NEO4J_USER}/${NEO4J_PASSWORD}
      NEO4J_PLUGINS: '["apoc"]'
    ports:
      - "7687:7687"
    volumes:
      - neo4j_data:/data
    healthcheck:
      test: ["CMD", "cypher-shell", "-u", "${NEO4J_USER}", "-p", "${NEO4J_PASSWORD}", "RETURN 1"]
      interval: 10s
      timeout: 5s
      retries: 5

  backend:
    build:
      context: .
      dockerfile: backend/Dockerfile.prod
    environment:
      DATABASE_URL: postgresql://cloudguard:${DB_PASSWORD}@postgres:5432/cloudguard
      REDIS_HOST: redis
      REDIS_PORT: 6379
      NEO4J_URI: bolt://neo4j:7687
      NEO4J_USER: ${NEO4J_USER}
      NEO4J_PASSWORD: ${NEO4J_PASSWORD}
      SECRET_KEY: ${SECRET_KEY}
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      neo4j:
        condition: service_healthy
    command: >
      sh -c "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"

volumes:
  postgres_data:
  neo4j_data:
```

---

## 14. GITHUB ACTIONS CI/CD

### `.github/workflows/test.yml`

```yaml
name: Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: cloudguard_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      
      redis:
        image: redis:7-alpine
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379

    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r backend/requirements.txt
        pip install pytest pytest-cov
    
    - name: Run tests
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/cloudguard_test
        REDIS_HOST: localhost
        REDIS_PORT: 6379
        NEO4J_URI: bolt://neo4j:7687
        SECRET_KEY: test-key
      run: |
        cd backend
        pytest tests/ -v --cov=app --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

---

## 15. ENVIRONMENT VARIABLES TEMPLATE

### `.env.example`

```bash
# Database
DATABASE_URL=postgresql://cloudguard:password@localhost:5432/cloudguard
DB_PASSWORD=your_secure_password

# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_neo4j_password

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# JWT/Security
SECRET_KEY=your_secret_key_here_min_32_chars
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=7

# FastAPI
ENVIRONMENT=production
DEBUG=False

# Stripe (Phase 3)
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...

# Sentry (Phase 2)
SENTRY_DSN=https://...@sentry.io/...
```

---

## 16. UNIT TEST EXAMPLE

### `backend/tests/unit/auth/test_register.py`

```python
"""Tests for user registration."""
import pytest
from sqlalchemy.orm import Session
from app.auth.service import AuthService, UserAlreadyExistsError
from app.auth.models import User, Organization

def test_register_new_user(db_session: Session):
    """Test successful user registration."""
    service = AuthService(db_session)
    
    user, org, access_token, refresh_token = service.register_user(
        email="test@example.com",
        password="securepassword123",
        organization_name="Test Org"
    )
    
    assert user.email == "test@example.com"
    assert org.name == "Test Org"
    assert access_token is not None
    assert refresh_token is not None

def test_register_duplicate_email(db_session: Session):
    """Test that duplicate email registration fails."""
    service = AuthService(db_session)
    
    # Register first user
    service.register_user(
        email="test@example.com",
        password="securepassword123",
        organization_name="Test Org 1"
    )
    
    # Try to register with same email
    with pytest.raises(UserAlreadyExistsError):
        service.register_user(
            email="test@example.com",
            password="anotherpassword123",
            organization_name="Test Org 2"
        )
```

---

## QUICK START CHECKLIST

✅ Copy all scaffolds above  
✅ Run database migrations: `alembic upgrade head`  
✅ Create environment file: `cp .env.example .env`  
✅ Start services: `docker-compose -f docker-compose.prod.yml up -d`  
✅ Run tests: `pytest backend/tests/ -v`  
✅ Start backend: `uvicorn app.main:app --reload`  
✅ Test endpoints:
```bash
# Register
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepass123",
    "organization_name": "My Company"
  }'

# Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepass123"
  }'

# Protected endpoint with token
curl http://localhost:8000/attack-path?start=Internet&target=Database \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

**End of Phase 1 Implementation Guide**
