# Code Scanner Agent 🔍

**Intelligent code scanning system with AI-powered validation and user authentication** that analyzes repositories for security vulnerabilities, code quality issues, and provides comprehensive reports.

## ✨ Features

### 🔐 Authentication & User Management
- **User Registration & Login** - Secure JWT-based authentication
- **Password Security** - Strong password hashing with pbkdf2_sha256
- **Session Management** - Persistent user sessions with token-based auth
- **Guest Mode** - Scan without registration (results not saved)
- **User-Specific Data** - Each user's scans are isolated and private

### 🛡️ Security Scanning
- **Multi-Tool Analysis** - Bandit, Pylint, Semgrep integration
- **Vulnerability Detection** - SQL injection, XSS, hardcoded secrets
- **Security Severity Levels** - Critical, High, Medium, Low classification
- **Manual Pattern Detection** - Custom security rules

### 📊 Code Quality Analysis
- **Code Complexity** - Cyclomatic complexity analysis
- **Best Practices** - PEP 8, coding standards validation
- **Maintainability** - Code smell detection
- **Documentation** - Missing docstrings and comments detection
- **Performance Issues** - Inefficient code patterns

### 🤖 AI-Powered Features
- **Groq LLM Integration** - Intelligent code analysis
- **Repository Validation** - AI verifies unit test authenticity
- **Smart Recommendations** - Context-aware code improvements
- **Confidence Scoring** - AI validation confidence levels

### 📱 Modern Web Interface
- **Responsive Design** - Works on desktop, tablet, and mobile
- **Dark/Light Theme** - User preference theme switching
- **Real-time Status** - Live scan progress updates
- **Interactive Reports** - Expandable issue details
- **Download Options** - PDF, JSON, TXT, DOCX formats

### 🔍 Unit Test Validation
- **Mandatory Test Reports** - Ensures code is tested
- **Repository Matching** - Validates test-code correlation
- **Multi-Method Verification** - Metadata, file paths, AI analysis
- **Test Coverage Display** - Visual test statistics

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
Create a `.env` file in the project root:
```bash
# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/code_scanner_db

# Authentication (IMPORTANT: Change in production!)
SECRET_KEY=your-super-secret-key-here-change-in-production

# AI Integration (Optional - for enhanced analysis)
GROQ_API_KEY=your_groq_api_key_here

# Application Settings
ENVIRONMENT=development
```

### 3. Initialize Database
```bash
# The database will be automatically created on first run
# Make sure PostgreSQL is running
```

### 4. Run Application

**Option A: Combined Mode (Recommended for development)**
```bash
python3 run_app.py
```
- 🌐 Web UI: http://localhost:8001
- 📚 API Docs: http://localhost:8001/docs

**Option B: Separate Mode (For production/advanced usage)**
```bash
# Terminal 1: Backend API Server
python3 run_app.py --backend

# Terminal 2: Frontend UI Server
python3 run_app.py --frontend
```
- 🌐 Web UI: http://localhost:8000
- 🔌 Backend API: http://localhost:8001
- 📚 API Docs: http://localhost:8001/docs

## 📁 Project Structure

```
CodeScannerAgent/
├── Back-End/
│   ├── code_scan_api.py          # FastAPI application & endpoints
│   ├── scanner.py                # Core scanning engine
│   ├── database.py               # PostgreSQL database operations
│   ├── auth.py                   # Authentication & JWT management
│   ├── unit_test_validator.py    # Test report validation
│   ├── llm_integration.py        # Groq AI integration
│   ├── report_generator.py       # Report generation logic
│   └── security_booster.py       # Additional security checks
├── Front-End/
│   ├── index.html                # Main web interface
│   ├── script.js                 # Frontend application logic
│   ├── api.js                    # API service layer
│   └── styles.css                # UI styling & themes
├── run_app.py                    # Application launcher
├── requirements.txt              # Python dependencies
├── .env                          # Environment configuration
└── README.md                     # This file
```

## 🔧 API Endpoints

### Authentication Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/auth/register` | POST | No | Register new user |
| `/api/auth/login` | POST | No | Login and get JWT token |
| `/api/auth/me` | GET | Yes | Get current user info |

### Scan Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/scan` | POST | Optional | Start new scan (guest or user) |
| `/api/scan/{job_id}` | GET | Optional* | Get scan status |
| `/api/scan/{job_id}/report` | GET | Optional* | Get detailed report |
| `/api/scans` | GET | Yes | List all user scans |
| `/api/scan/{job_id}` | DELETE | Yes | Delete a scan |
| `/api/scans/clear` | DELETE | Yes | Clear all user scans |

*Optional auth with ownership validation - users can only access their own scans

### Download Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/download/{job_id}/json` | GET | Optional* | Download JSON report |
| `/api/download/{job_id}/pdf` | GET | Optional* | Download PDF report |
| `/api/download/{job_id}/txt` | GET | Optional* | Download TXT report |
| `/api/download/{job_id}/docx` | GET | Optional* | Download DOCX report |

### Utility Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/health` | GET | No | Health check |

## 💡 Usage Guide

### Web Interface

1. **Register/Login** (Optional - can use guest mode)
   - Click "Register" to create an account
   - Or click "Login" if you already have an account
   - Or proceed as guest (scans won't be saved)

2. **Start a Scan**
   - Enter GitHub repository URL
   - Upload unit test report (JSON format - **Required**)
   - Optionally upload PRD document for context
   - Click "Start Scan"

3. **Monitor Progress**
   - Real-time status updates
   - Progress bar showing scan stages
   - Estimated completion time

4. **View Results**
   - Comprehensive issue breakdown
   - Security, quality, and best practice violations
   - Unit test summary and coverage
   - Minimal fix suggestions

5. **Download Reports**
   - Multiple format options (PDF, JSON, TXT, DOCX)
   - View online or download
   - Share with team members

### API Usage Examples

**Register User:**
```bash
curl -X POST http://localhost:8001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepass123",
    "full_name": "John Doe"
  }'
```

**Login:**
```bash
curl -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user@example.com&password=securepass123"
```

**Start Scan (with authentication):**
```bash
curl -X POST http://localhost:8001/api/scan \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -F "repo_url=https://github.com/username/repository.git" \
  -F "unit_test_report=@test_report.json"
```

**Check Scan Status:**
```bash
curl -X GET http://localhost:8001/api/scan/{job_id} \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**Download Report:**
```bash
curl -X GET http://localhost:8001/api/download/{job_id}/json \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -o report.json
```

## 🤖 AI Validation System

The intelligent validator uses **Groq's Llama model** to analyze:

### Validation Checks
- ✅ Repository structure and file organization
- ✅ Unit test report authenticity
- ✅ Code-test file path correlation
- ✅ Framework and language alignment
- ✅ Test naming conventions
- ✅ Coverage metrics validation

### Confidence Levels
- 🟢 **High (70%+)**: Auto-approved, high confidence match
- 🟡 **Medium (50-70%)**: Additional pattern checks applied
- 🔴 **Low (<50%)**: Rejected with detailed reason

### Multi-Layer Validation
1. **Metadata Check** - Repository name, language, framework
2. **File Path Validation** - Test files exist in repository
3. **AI Analysis** - Deep semantic validation
4. **Post-Clone Verification** - Actual repository content check

## 🛡️ Security Features

### Authentication Security
- ✅ JWT token-based authentication
- ✅ Password hashing with pbkdf2_sha256
- ✅ Automatic hash migration from bcrypt
- ✅ 24-hour token expiration
- ✅ Secure session management

### Data Security
- ✅ User-specific data isolation
- ✅ Ownership validation on all operations
- ✅ SQL injection prevention
- ✅ CORS protection
- ✅ Input sanitization

### Scan Security
- ✅ Multi-layer validation prevents fake reports
- ✅ Repository cloning for actual code analysis
- ✅ Pattern-based vulnerability detection
- ✅ AI-enhanced false positive reduction

## 📊 Scan Results

### Issue Categories
- **Security Issues**: Vulnerabilities with severity levels (Critical/High/Medium/Low)
- **Quality Issues**: Code smells, complexity, maintainability
- **Performance Issues**: Inefficient patterns, optimization opportunities
- **Best Practice Issues**: Coding standards violations
- **Documentation Issues**: Missing docstrings, comments
- **Maintainability Issues**: Code organization, modularity

### Report Features
- **Detailed Descriptions**: Clear explanation of each issue
- **File Locations**: Exact file and line numbers
- **Severity Levels**: Risk assessment for prioritization
- **Fix Suggestions**: Actionable recommendations
- **Minimal Code Suggestions**: Simplified fix approaches
- **Unit Test Summary**: Test coverage and results

### Download Formats
- **JSON**: Machine-readable, API integration
- **PDF**: Professional, shareable reports
- **TXT**: Simple, readable format
- **DOCX**: Editable Word documents

## 🔧 Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `SECRET_KEY` | Yes | (dev key) | JWT signing key - **MUST change in production** |
| `GROQ_API_KEY` | No | - | Groq AI API key for enhanced analysis |
| `ENVIRONMENT` | No | development | Environment mode |

### Database Setup

The application uses **PostgreSQL** for data persistence:

```sql
-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scans table
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    job_id VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id),
    repo_url TEXT NOT NULL,
    status VARCHAR(50) NOT NULL,
    -- ... additional columns
);
```

## 🚀 Deployment

### Production Checklist

> **IMPORTANT**: Before deploying to production:

1. ✅ Set strong `SECRET_KEY` in environment variables
2. ✅ Configure `DATABASE_URL` with production database
3. ✅ Restrict CORS origins to your domain
4. ✅ Enable HTTPS/SSL
5. ✅ Set `ENVIRONMENT=production`
6. ✅ Configure proper logging
7. ✅ Set up database backups
8. ✅ Add rate limiting (recommended)
9. ✅ Configure monitoring (Sentry, DataDog, etc.)
10. ✅ Review and update password requirements

### Recommended Stack
- **Web Server**: Nginx or Caddy (reverse proxy)
- **WSGI Server**: Gunicorn or Uvicorn
- **Database**: PostgreSQL 12+
- **SSL**: Let's Encrypt
- **Monitoring**: Sentry, Prometheus, Grafana

## 🧪 Testing

### Manual Testing
```bash
# Health check
curl http://localhost:8001/api/health

# Test registration
curl -X POST http://localhost:8001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test1234","full_name":"Test"}'
```

### Unit Test Report Format
```json
{
  "repository": "username/repo-name",
  "language": "Python",
  "framework": "pytest",
  "total_tests": 50,
  "passed": 45,
  "failed": 5,
  "coverage_percent": 85.5,
  "test_details": [
    {
      "name": "test_user_authentication",
      "file": "tests/test_auth.py",
      "status": "PASSED",
      "duration": "0.05s"
    }
  ]
}
```

## 📝 Changelog

### Version 2.0.0 (Current)
- ✅ Added user authentication system
- ✅ JWT token-based security
- ✅ User-specific scan history
- ✅ Guest mode support
- ✅ Separated frontend and backend
- ✅ PostgreSQL database integration
- ✅ Enhanced API documentation

### Version 1.0.0
- ✅ Initial release
- ✅ Basic code scanning
- ✅ AI validation
- ✅ Report generation

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For issues, questions, or feature requests:
- Create an issue on GitHub
- Contact: support@example.com

---

**Built with FastAPI, PostgreSQL, and Groq AI** 🚀

**Tech Stack:**
- Backend: FastAPI, Python 3.8+
- Frontend: Vanilla JavaScript, HTML5, CSS3
- Database: PostgreSQL
- Authentication: JWT (python-jose)
- Security: Bandit, Pylint, Semgrep
- AI: Groq Llama Model
- Reports: FPDF, python-docx
# CodeScanningAgent
