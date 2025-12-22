class ApiService {
    constructor(baseUrl = '/api') {
        const PRODUCTION_BACKEND_URL = 'https://code-scanner-backend.onrender.com/api'; // user to replace this

        // If running on localhost/127.0.0.1, assume decoupled local dev
        const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';

        if (isLocal) {
            // Local Development: Point to Backend Port 8001
            if (window.location.port !== '8001') {
                this.baseUrl = `http://${window.location.hostname}:8001${baseUrl}`;
                console.log(`📡 Local Dev Mode: Connected to ${this.baseUrl}`);
            } else {
                this.baseUrl = baseUrl;
            }
        } else {
            // Production (Vercel): Use the Render URL
            this.baseUrl = PRODUCTION_BACKEND_URL;
            console.log(`🚀 Production Mode: Connected to ${this.baseUrl}`);
        }
    }


    _getHeaders() {
        const headers = {};
        const token = localStorage.getItem('token');
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        return headers;
    }

    async _fetch(url, options = {}) {
        const headers = {
            ...this._getHeaders(),
            ...options.headers
        };

        const response = await fetch(url, { ...options, headers });
        if (response.status === 401) {
            // Unauthorized - clear token and potentially redirect
            localStorage.removeItem('token');
            // Allow caller to handle redirect if needed
        }
        return response;
    }

    // --- Auth Methods ---

    async login(email, password) {
        // OAuth2PasswordRequestForm expects x-www-form-urlencoded
        const formData = new URLSearchParams();
        formData.append('username', email);
        formData.append('password', password);

        const response = await fetch(`${this.baseUrl}/auth/login`, {
            method: 'POST',
            body: formData,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        if (!response.ok) {
            let errorMessage = 'Login failed';
            try {
                const error = await response.json();
                errorMessage = error.detail || errorMessage;
            } catch (e) {
                const text = await response.text();
                errorMessage = text || `HTTP error! status: ${response.status}`;
            }
            throw new Error(errorMessage);
        }

        const data = await response.json();
        localStorage.setItem('token', data.access_token);
        return data;
    }

    async register(email, password, fullName) {
        const response = await fetch(`${this.baseUrl}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, full_name: fullName })
        });

        if (!response.ok) {
            let errorMessage = 'Registration failed';
            try {
                const error = await response.json();
                errorMessage = error.detail || errorMessage;
            } catch (e) {
                const text = await response.text();
                errorMessage = text || `HTTP error! status: ${response.status}`;
            }
            throw new Error(errorMessage);
        }

        return await response.json();
    }

    logout() {
        localStorage.removeItem('token');
    }

    isLoggedIn() {
        return !!localStorage.getItem('token');
    }

    async getMe() {
        const response = await this._fetch(`${this.baseUrl}/auth/me`);
        if (!response.ok) {
            // Throw specific error without trying to parse JSON if status is bad
            throw new Error('Failed to fetch user profile');
        }
        return await response.json();
    }

    // --- Scan Methods ---

    async clearAllScans() {
        const response = await this._fetch(`${this.baseUrl}/scans/clear`, {
            method: 'DELETE'
        });
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || `HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }

    async startScan(formData) {
        const response = await this._fetch(`${this.baseUrl}/scan`, {
            method: 'POST',
            body: formData
        });
        if (!response.ok) {
            let errorMessage = `HTTP error! status: ${response.status}`;
            try {
                const errorData = await response.json();
                errorMessage = errorData.detail || errorMessage;
            } catch {
                const errorText = await response.text();
                console.error('Error response:', errorText);
            }
            throw new Error(errorMessage);
        }
        return await response.json();
    }

    async getScanStatus(jobId) {
        const response = await this._fetch(`${this.baseUrl}/scan/${jobId}`);
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || `HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }

    async getScanReport(jobId) {
        const response = await this._fetch(`${this.baseUrl}/scan/${jobId}/report`);
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || `HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }

    async listScans() {
        const response = await this._fetch(`${this.baseUrl}/scans`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }

    async deleteScan(jobId) {
        const response = await this._fetch(`${this.baseUrl}/scan/${jobId}`, {
            method: 'DELETE'
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }

    getDownloadUrl(jobId, format, view = false) {
        let url = `${this.baseUrl}/download/${jobId}/${format}`;
        const token = localStorage.getItem('token');
        const params = new URLSearchParams();
        if (view) params.append('view', 'true');
        if (token) params.append('token', token); // Optional: if backend supports token in query

        const queryString = params.toString();
        return queryString ? `${url}?${queryString}` : url;
    }
}

// Export for use in other scripts
window.ApiService = ApiService;
