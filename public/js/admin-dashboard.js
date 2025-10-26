// Admin Dashboard JavaScript
let socket;
let currentSection = 'dashboard';
let autoDeleteEnabled = false;
let tokenCountdownIntervals = new Map();
let sessionCountdownIntervals = new Map();

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function () {
    initializeSocket();
    initializeSidebar();
    initializeBottomNav();
    loadDashboardStats();
    loadInitialData();

    // Set up event listeners
    setupEventListeners();

    // Refresh data every 30 seconds
    setInterval(loadDashboardStats, 30000);
});

// Initialize Socket.io connection
function initializeSocket() {
    socket = io();
    socket.on('connect', function () {
        console.log('Connected to server');
        socket.emit('join-admin');
        addRecentActivity('Connected to real-time server', 'success');
    });
    // Real-time event handlers
    socket.on('user-login-attempt', handleLoginAttempt);
    socket.on('token-verification', handleTokenVerification);
    socket.on('session-created', handleSessionCreated);
    socket.on('user-logout', handleUserLogout);
    socket.on('security-alert', handleSecurityAlert);
    socket.on('virtual-token-generated', handleVirtualTokenGenerated);
    socket.on('session-force-logout', handleSessionForceLogout);
    socket.on('token-expired', handleTokenExpired);
    socket.on('token-status-update', handleTokenStatusUpdate);

}

// Add new event handler for token status updates
function handleTokenStatusUpdate(data) {
    const { tokenId, newStatus } = data;

    // Update token in the tokens table if visible
    if (currentSection === 'tokens') {
        updateTokenStatusInUI(tokenId, newStatus);
    }

    // Refresh dashboard stats
    loadDashboardStats();

    addRecentActivity(`Token status updated to ${newStatus}`, 'info');
}

// Update token status in UI
function updateTokenStatusInUI(tokenId, newStatus) {
    // Update desktop table
    const tokenRow = document.querySelector(`#tokensTableBody tr td.status-badge`);
    if (tokenRow) {
        const statusBadge = tokenRow.querySelector('.status-badge');
        if (statusBadge) {
            statusBadge.textContent = newStatus;
            statusBadge.className = `status-badge ${getStatusClass(newStatus)}`;
        }
    }

    // Update mobile table
    const mobileToken = document.querySelector(`[id*="mobile-token-time-${tokenId}"]`);
    if (mobileToken) {
        const mobileStatus = mobileToken.closest('.mobile-table-card').querySelector('.status-badge');
        if (mobileStatus) {
            mobileStatus.textContent = newStatus;
            mobileStatus.className = `status-badge ${getStatusClass(newStatus)}`;
        }
    }

    // Stop countdown if token is no longer active
    if (newStatus !== 'ACTIVE' && tokenCountdownIntervals.has(tokenId)) {
        clearInterval(tokenCountdownIntervals.get(tokenId));
        tokenCountdownIntervals.delete(tokenId);
    }
}

// Initialize sidebar navigation
function initializeSidebar() {
    const sidebarItems = document.querySelectorAll('.sidebar-item');

    sidebarItems.forEach(item => {
        item.addEventListener('click', function (e) {
            e.preventDefault();

            // Remove active class from all items
            sidebarItems.forEach(i => i.classList.remove('active'));

            // Add active class to clicked item
            this.classList.add('active');

            // Show corresponding section
            const section = this.getAttribute('data-section');
            showSection(section);

            // Update bottom nav
            updateBottomNav(section);
        });
    });
}

// Initialize mobile bottom navigation
function initializeBottomNav() {
    const navItems = document.querySelectorAll('.mobile-nav-item');

    navItems.forEach(item => {
        item.addEventListener('click', function (e) {
            e.preventDefault();

            // Remove active class from all items
            navItems.forEach(i => i.classList.remove('active'));

            // Add active class to clicked item
            this.classList.add('active');

            // Show corresponding section
            const section = this.getAttribute('data-section');
            showSection(section);
        });
    });
}

// Update bottom navigation active state
function updateBottomNav(section) {
    const navItems = document.querySelectorAll('.mobile-nav-item');

    navItems.forEach(item => {
        if (item.getAttribute('data-section') === section) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });
}

// Show specific section
function showSection(sectionName) {
    // Hide all sections
    const sections = document.querySelectorAll('.section');
    sections.forEach(section => section.classList.add('hidden'));

    // Show selected section
    const targetSection = document.getElementById(`${sectionName}-section`);
    if (targetSection) {
        targetSection.classList.remove('hidden');
        currentSection = sectionName;

        // Load section-specific data
        loadSectionData(sectionName);
    }
}

// Load section-specific data
function loadSectionData(sectionName) {
    switch (sectionName) {
        case 'users':
            loadUsers();
            break;
        case 'tokens':
            loadTokens();
            break;
        case 'sessions':
            loadSessions();
            break;
        case 'dashboard':
            loadDashboardStats();
            break;
    }
}

// Load dashboard statistics
async function loadDashboardStats() {
    try {
        // Show loading state
        document.getElementById('totalUsers').textContent = '--';
        document.getElementById('activeTokens').textContent = '--';
        document.getElementById('activeSessions').textContent = '--';
        document.getElementById('expiredTokens').textContent = '--';

        const response = await fetch('/api/admin/dashboard-stats');
        const data = await response.json();

        if (data.success) {
            // Animate number counting
            animateValue('totalUsers', 0, data.stats.totalUsers, 1000);
            animateValue('activeTokens', 0, data.stats.activeTokens, 1000);
            animateValue('activeSessions', 0, data.stats.activeSessions, 1000);
            animateValue('expiredTokens', 0, data.stats.expiredTokens, 1000);

            autoDeleteEnabled = data.stats.autoDeleteEnabled;
            updateAutoDeleteStatus();
        }
    } catch (error) {
        console.error('Error loading dashboard stats:', error);
        addRecentActivity('Failed to load dashboard statistics', 'error');
    }
}

// Animate number counting
function animateValue(id, start, end, duration) {
    const obj = document.getElementById(id);
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        const value = Math.floor(progress * (end - start) + start);
        obj.textContent = value.toLocaleString();
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}

// Load users data
async function loadUsers() {
    try {
        const response = await fetch('/api/admin/users');
        const data = await response.json();

        if (data.success) {
            // Update desktop table
            const tbody = document.getElementById('usersTableBody');
            tbody.innerHTML = '';

            // Update mobile table
            const mobileTable = document.getElementById('usersMobileTable');
            mobileTable.innerHTML = '';

            if (data.users.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="4" class="px-6 py-12 text-center text-gray-500">
                            <div class="flex flex-col items-center">
                                <svg class="w-16 h-16 text-gray-300 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"></path>
                                </svg>
                                <p class="text-gray-500 text-lg">No users found</p>
                                <p class="text-gray-400 text-sm mt-1">Users will appear here once created</p>
                            </div>
                        </td>
                    </tr>
                `;
                mobileTable.innerHTML = `
                    <div class="text-center py-12 text-gray-500">
                        <svg class="w-16 h-16 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"></path>
                        </svg>
                        <p class="text-gray-500 text-lg">No users found</p>
                        <p class="text-gray-400 text-sm mt-1">Users will appear here once created</p>
                    </div>
                `;
                return;
            }

            // Desktop table
            data.users.forEach(user => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-gray-50 transition-all duration-200';
                row.innerHTML = `
                    <td class="px-6 py-4">
                        <div class="flex items-center">
                            <div class="w-10 h-10 bg-gradient-to-r from-primary to-secondary rounded-full flex items-center justify-center text-white font-semibold text-sm mr-4">
                                ${user.name.charAt(0).toUpperCase()}
                            </div>
                            <div>
                                <div class="text-sm font-semibold text-gray-900">${user.name}</div>
                                <div class="text-xs text-gray-500">${user.email || 'No email'}</div>
                            </div>
                        </div>
                    </td>
                    <td class="px-6 py-4 text-sm text-gray-900 font-medium">${user.username}</td>
                    <td class="px-6 py-4">
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 font-mono">
                            ${user.vauth_device_ID}
                        </span>
                    </td>
                    <td class="px-6 py-4 text-sm text-gray-500">${formatDate(user.created_at)}</td>
                `;
                tbody.appendChild(row);
            });

            // Mobile cards
            data.users.forEach(user => {
                const card = document.createElement('div');
                card.className = 'mobile-table-card';
                card.innerHTML = `
                    <div class="flex items-center mb-4">
                        <div class="w-12 h-12 bg-gradient-to-r from-primary to-secondary rounded-full flex items-center justify-center text-white font-semibold text-lg mr-4">
                            ${user.name.charAt(0).toUpperCase()}
                        </div>
                        <div class="flex-1">
                            <h3 class="font-semibold text-gray-900 text-lg">${user.name}</h3>
                            <p class="text-gray-600 text-sm">${user.username}</p>
                            ${user.email ? `<p class="text-gray-500 text-xs mt-1">${user.email}</p>` : ''}
                        </div>
                    </div>
                    <div class="space-y-3">
                        <div class="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                            <span class="text-sm font-medium text-gray-700">Device ID</span>
                            <span class="text-sm font-mono text-primary font-semibold">${user.vauth_device_ID}</span>
                        </div>
                        <div class="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                            <span class="text-sm font-medium text-gray-700">Created</span>
                            <span class="text-sm text-gray-600">${formatDate(user.created_at)}</span>
                        </div>
                    </div>
                `;
                mobileTable.appendChild(card);
            });
        }
    } catch (error) {
        console.error('Error loading users:', error);
        addRecentActivity('Failed to load user data', 'error');
    }
}

// Load tokens data
async function loadTokens() {
    try {
        // Clear existing countdown intervals
        clearAllTokenCountdowns();

        const response = await fetch('/api/admin/tokens');
        const data = await response.json();

        if (data.success) {
            // Update desktop table
            const tbody = document.getElementById('tokensTableBody');
            tbody.innerHTML = '';
            autoDeleteEnabled = data.autoDeleteEnabled;
            updateAutoDeleteStatus();

            // Update mobile table
            const mobileTable = document.getElementById('tokensMobileTable');
            mobileTable.innerHTML = '';

            if (data.tokens.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="5" class="px-6 py-12 text-center text-gray-500">
                            <div class="flex flex-col items-center">
                                <svg class="w-16 h-16 text-gray-300 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path>
                                </svg>
                                <p class="text-gray-500 text-lg">No tokens found</p>
                                <p class="text-gray-400 text-sm mt-1">Tokens will appear here once generated</p>
                            </div>
                        </td>
                    </tr>
                `;
                mobileTable.innerHTML = `
                    <div class="text-center py-12 text-gray-500">
                        <svg class="w-16 h-16 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path>
                        </svg>
                        <p class="text-gray-500 text-lg">No tokens found</p>
                        <p class="text-gray-400 text-sm mt-1">Tokens will appear here once generated</p>
                    </div>
                `;
                return;
            }

            // Desktop table
            data.tokens.forEach(token => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-gray-50 transition-all duration-200';
                const statusClass = getStatusClass(token.status);
                const timeRemaining = token.status === 'ACTIVE' ? formatTime(token.timeRemaining) : '--';

                row.innerHTML = `
                    <td class="px-6 py-4">
                        <span class="font-mono text-sm font-semibold text-gray-900">${token.device_id}</span>
                    </td>
                    <td class="px-6 py-4">
                        <span class="status-badge ${statusClass}">
                            ${token.status}
                        </span>
                    </td>
                    <td class="px-6 py-4">
                        <span id="token-time-${token._id}" class="text-sm font-medium ${token.status === 'ACTIVE' && token.timeRemaining < 60 ? 'text-red-600' : 'text-gray-700'}">
                            ${timeRemaining}
                        </span>
                    </td>
                    <td class="px-6 py-4 text-sm text-gray-500">${formatDate(token.created_at)}</td>
                    <td class="px-6 py-4">
                        <button onclick="deleteToken('${token._id}')" class="text-red-600 hover:text-red-800 transition-colors duration-200 font-medium text-sm bg-red-50 hover:bg-red-100 px-3 py-1 rounded-lg">
                            Delete
                        </button>
                    </td>
                `;
                tbody.appendChild(row);

                // Start countdown for active tokens
                if (token.status === 'ACTIVE' && token.timeRemaining > 0) {
                    startTokenCountdown(token._id, token.timeRemaining);
                }
            });

            // Mobile cards - Enhanced design
            data.tokens.forEach(token => {
                const card = document.createElement('div');
                card.className = 'mobile-table-card';
                const timeRemaining = token.status === 'ACTIVE' ? formatTime(token.timeRemaining) : '--';
                const statusBadge = getMobileStatusBadge(token.status);
                const isExpiring = token.status === 'ACTIVE' && token.timeRemaining < 60;

                card.innerHTML = `
                    <div class="flex justify-between items-start mb-4">
                        <div class="flex-1">
                            <div class="flex items-center gap-2 mb-2">
                                <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path>
                                </svg>
                                <span class="font-mono text-sm font-semibold text-gray-900">${token.device_id}</span>
                            </div>
                            ${statusBadge}
                        </div>
                    </div>
                    
                    <div class="grid grid-cols-2 gap-3 mb-4">
                        <div class="bg-gray-50 rounded-lg p-3 text-center">
                            <div class="text-xs text-gray-500 mb-1">Time Remaining</div>
                            <div id="mobile-token-time-${token._id}" class="text-sm font-semibold ${isExpiring ? 'text-red-600' : 'text-gray-900'}">
                                ${timeRemaining}
                            </div>
                        </div>
                        <div class="bg-gray-50 rounded-lg p-3 text-center">
                            <div class="text-xs text-gray-500 mb-1">Created</div>
                            <div class="text-sm font-semibold text-gray-900">${formatDateShort(token.created_at)}</div>
                        </div>
                    </div>
                    
                    <div class="flex justify-end">
                        <button onclick="deleteToken('${token._id}')" class="text-red-600 hover:text-red-800 transition-colors duration-200 font-medium text-sm bg-red-50 hover:bg-red-100 px-4 py-2 rounded-lg flex items-center gap-2">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                            </svg>
                            Delete Token
                        </button>
                    </div>
                `;
                mobileTable.appendChild(card);

                // Start countdown for active tokens on mobile
                if (token.status === 'ACTIVE' && token.timeRemaining > 0) {
                    startMobileTokenCountdown(token._id, token.timeRemaining);
                }
            });
        }
    } catch (error) {
        console.error('Error loading tokens:', error);
        addRecentActivity('Failed to load token data', 'error');
    }
}

// Start countdown for token time remaining
function startTokenCountdown(tokenId, initialSeconds) {
    // Clear any existing interval for this token
    if (tokenCountdownIntervals.has(tokenId)) {
        clearInterval(tokenCountdownIntervals.get(tokenId));
    }

    let seconds = initialSeconds;
    const timeElement = document.getElementById(`token-time-${tokenId}`);

    const interval = setInterval(() => {
        seconds--;

        if (seconds <= 0) {
            timeElement.textContent = '00:00';
            timeElement.className = 'text-red-600 font-semibold';
            clearInterval(interval);
            tokenCountdownIntervals.delete(tokenId);

            // Update token status to expired
            updateTokenStatus(tokenId, 'EXPIRED');
            return;
        }

        // Add warning class when less than 60 seconds
        if (seconds < 60) {
            timeElement.className = 'text-red-600 font-semibold';
        }

        timeElement.textContent = formatTime(seconds);
    }, 1000);

    tokenCountdownIntervals.set(tokenId, interval);
}

// Start countdown for mobile token time remaining
function startMobileTokenCountdown(tokenId, initialSeconds) {
    let seconds = initialSeconds;
    const timeElement = document.getElementById(`mobile-token-time-${tokenId}`);

    const interval = setInterval(() => {
        seconds--;

        if (seconds <= 0) {
            timeElement.textContent = '00:00';
            timeElement.className = 'text-red-600 font-semibold';
            clearInterval(interval);
            return;
        }

        // Add warning class when less than 60 seconds
        if (seconds < 60) {
            timeElement.className = 'text-red-600 font-semibold';
        }

        timeElement.textContent = formatTime(seconds);
    }, 1000);
}

// Clear all token countdown intervals
function clearAllTokenCountdowns() {
    tokenCountdownIntervals.forEach((interval, tokenId) => {
        clearInterval(interval);
    });
    tokenCountdownIntervals.clear();
}

// Update token status when expired
function updateTokenStatus(tokenId, newStatus) {
    // Find the token row and update its status
    const statusElement = document.querySelector(`#tokensTableBody tr td .status-badge`);
    if (statusElement) {
        statusElement.textContent = newStatus;
        statusElement.className = `status-badge ${getStatusClass(newStatus)}`;
    }

    // Update dashboard stats
    loadDashboardStats();
}

// Load sessions data
async function loadSessions() {
    try {
        // Clear existing countdown intervals
        clearAllSessionCountdowns();

        const response = await fetch('/api/admin/sessions');
        const data = await response.json();

        if (data.success) {
            // Update desktop table
            const tbody = document.getElementById('sessionsTableBody');
            tbody.innerHTML = '';

            // Update mobile table
            const mobileTable = document.getElementById('sessionsMobileTable');
            mobileTable.innerHTML = '';

            if (data.sessions.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6" class="px-6 py-12 text-center text-gray-500">
                            <div class="flex flex-col items-center">
                                <svg class="w-16 h-16 text-gray-300 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                                </svg>
                                <p class="text-gray-500 text-lg">No active sessions</p>
                                <p class="text-gray-400 text-sm mt-1">Active sessions will appear here</p>
                            </div>
                        </td>
                    </tr>
                `;
                mobileTable.innerHTML = `
                    <div class="text-center py-12 text-gray-500">
                        <svg class="w-16 h-16 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                        </svg>
                        <p class="text-gray-500 text-lg">No active sessions</p>
                        <p class="text-gray-400 text-sm mt-1">Active sessions will appear here</p>
                    </div>
                `;
                return;
            }

            // Desktop table
            data.sessions.forEach(session => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-gray-50 transition-all duration-200';
                const isExpiring = session.timeRemaining < 300; // 5 minutes

                row.innerHTML = `
                    <td class="px-6 py-4">
                        <div class="text-sm font-semibold text-gray-900">${session.username}</div>
                    </td>
                    <td class="px-6 py-4">
                        <span class="font-mono text-sm text-gray-700">${session.device_id}</span>
                    </td>
                    <td class="px-6 py-4">
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                            ${session.ip}
                        </span>
                    </td>
                    <td class="px-6 py-4 text-sm text-gray-500">${formatDate(session.started_at)}</td>
                    <td class="px-6 py-4">
                        <span id="session-time-${session._id}" class="text-sm font-medium ${isExpiring ? 'text-red-600' : 'text-gray-700'}">
                            ${formatTime(session.timeRemaining)}
                        </span>
                    </td>
                    <td class="px-6 py-4">
                        <button onclick="forceLogout('${session._id}')" class="text-red-600 hover:text-red-800 transition-colors duration-200 font-medium text-sm bg-red-50 hover:bg-red-100 px-3 py-1 rounded-lg">
                            Force Logout
                        </button>
                    </td>
                `;
                tbody.appendChild(row);

                // Start countdown for session time remaining
                if (session.timeRemaining > 0) {
                    startSessionCountdown(session._id, session.timeRemaining);
                }
            });

            // Mobile cards
            data.sessions.forEach(session => {
                const card = document.createElement('div');
                card.className = 'mobile-table-card';
                const isExpiring = session.timeRemaining < 300;

                card.innerHTML = `
                    <div class="flex justify-between items-start mb-4">
                        <div class="flex-1">
                            <h3 class="font-semibold text-gray-900 text-lg mb-1">${session.username}</h3>
                            <div class="flex items-center gap-2 text-sm text-gray-600">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path>
                                </svg>
                                <span>${session.ip}</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="grid grid-cols-2 gap-3 mb-4">
                        <div class="bg-gray-50 rounded-lg p-3">
                            <div class="text-xs text-gray-500 mb-1">Device ID</div>
                            <div class="text-sm font-mono text-gray-900 font-semibold">${session.device_id}</div>
                        </div>
                        <div class="bg-gray-50 rounded-lg p-3">
                            <div class="text-xs text-gray-500 mb-1">Time Left</div>
                            <div id="mobile-session-time-${session._id}" class="text-sm font-semibold ${isExpiring ? 'text-red-600' : 'text-gray-900'}">
                                ${formatTime(session.timeRemaining)}
                            </div>
                        </div>
                    </div>
                    
                    <div class="flex items-center justify-between text-sm text-gray-500 mb-4">
                        <span>Started: ${formatDateShort(session.started_at)}</span>
                    </div>
                    
                    <div class="flex justify-end">
                        <button onclick="forceLogout('${session._id}')" class="text-red-600 hover:text-red-800 transition-colors duration-200 font-medium text-sm bg-red-50 hover:bg-red-100 px-4 py-2 rounded-lg flex items-center gap-2">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path>
                            </svg>
                            Force Logout
                        </button>
                    </div>
                `;
                mobileTable.appendChild(card);

                // Start countdown for session time remaining on mobile
                if (session.timeRemaining > 0) {
                    startMobileSessionCountdown(session._id, session.timeRemaining);
                }
            });
        }
    } catch (error) {
        console.error('Error loading sessions:', error);
        addRecentActivity('Failed to load session data', 'error');
    }
}

// Start countdown for session time remaining
function startSessionCountdown(sessionId, initialSeconds) {
    // Clear any existing interval for this session
    if (sessionCountdownIntervals.has(sessionId)) {
        clearInterval(sessionCountdownIntervals.get(sessionId));
    }

    let seconds = initialSeconds;
    const timeElement = document.getElementById(`session-time-${sessionId}`);

    const interval = setInterval(() => {
        seconds--;

        if (seconds <= 0) {
            timeElement.textContent = '00:00';
            timeElement.className = 'text-red-600 font-semibold';
            clearInterval(interval);
            sessionCountdownIntervals.delete(sessionId);
            return;
        }

        // Add warning class when less than 5 minutes
        if (seconds < 300) {
            timeElement.className = 'text-red-600 font-semibold';
        }

        timeElement.textContent = formatTime(seconds);
    }, 1000);

    sessionCountdownIntervals.set(sessionId, interval);
}

// Start countdown for mobile session time remaining
function startMobileSessionCountdown(sessionId, initialSeconds) {
    let seconds = initialSeconds;
    const timeElement = document.getElementById(`mobile-session-time-${sessionId}`);

    const interval = setInterval(() => {
        seconds--;

        if (seconds <= 0) {
            timeElement.textContent = '00:00';
            timeElement.className = 'text-red-600 font-semibold';
            clearInterval(interval);
            return;
        }

        // Add warning class when less than 5 minutes
        if (seconds < 300) {
            timeElement.className = 'text-red-600 font-semibold';
        }

        timeElement.textContent = formatTime(seconds);
    }, 1000);
}

// Clear all session countdown intervals
function clearAllSessionCountdowns() {
    sessionCountdownIntervals.forEach((interval, sessionId) => {
        clearInterval(interval);
    });
    sessionCountdownIntervals.clear();
}

// Setup event listeners
function setupEventListeners() {
    // Logout button
    document.getElementById('logoutButton').addEventListener('click', logout);

    // Add user form
    document.getElementById('addUserForm').addEventListener('submit', handleAddUser);

    // Virtual token form
    document.getElementById('virtualTokenForm').addEventListener('submit', handleVirtualToken);

    // Refresh buttons
    document.getElementById('refreshUsers').addEventListener('click', loadUsers);
    document.getElementById('refreshTokens').addEventListener('click', loadTokens);
    document.getElementById('refreshSessions').addEventListener('click', loadSessions);

    // Auto-delete toggle
    document.getElementById('toggleAutoDelete').addEventListener('click', toggleAutoDelete);

    // Alert modal close
    document.getElementById('closeAlert').addEventListener('click', closeAlert);
}

// Handle add user form submission
async function handleAddUser(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const userData = Object.fromEntries(formData);

    try {
        const response = await fetch('/api/admin/add-user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData)
        });

        const data = await response.json();

        if (data.success) {
            // Show generated credentials
            document.getElementById('genUsername').textContent = data.credentials.username;
            document.getElementById('genPassword').textContent = data.credentials.password;
            document.getElementById('genDeviceId').textContent = data.credentials.vauth_device_ID;
            document.getElementById('credentialsDisplay').classList.remove('hidden');

            // Reset form
            e.target.reset();

            // Refresh stats
            loadDashboardStats();

            addRecentActivity(`New user created: ${userData.name}`, 'success');
        } else {
            showAlert('Error creating user: ' + data.message);
            addRecentActivity(`Failed to create user: ${userData.name}`, 'error');
        }
    } catch (error) {
        console.error('Error adding user:', error);
        showAlert('Network error. Please try again.');
        addRecentActivity('Network error while creating user', 'error');
    }
}

// Handle virtual token generation
async function handleVirtualToken(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const deviceId = formData.get('device_id');

    try {
        const response = await fetch('/api/admin/virtual-device/generate-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ device_id: deviceId })
        });

        const data = await response.json();

        if (data.success) {
            // Show generated token
            document.getElementById('generatedToken').textContent = data.token;
            document.getElementById('tokenExpiry').textContent = formatDate(data.expires_at);
            document.getElementById('tokenDisplay').classList.remove('hidden');

            // Reset form
            e.target.reset();

            addRecentActivity(`Virtual token generated for device ${deviceId}`, 'success');
        } else {
            showAlert('Error generating token: ' + data.message);
            addRecentActivity(`Failed to generate token for device ${deviceId}`, 'error');
        }
    } catch (error) {
        console.error('Error generating virtual token:', error);
        showAlert('Network error. Please try again.');
        addRecentActivity('Network error while generating token', 'error');
    }
}

// Delete token
async function deleteToken(tokenId) {
    if (!confirm('Are you sure you want to delete this token?')) {
        return;
    }

    try {
        const response = await fetch(`/api/admin/tokens/${tokenId}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (data.success) {
            // Clear countdown for this token
            if (tokenCountdownIntervals.has(tokenId)) {
                clearInterval(tokenCountdownIntervals.get(tokenId));
                tokenCountdownIntervals.delete(tokenId);
            }

            loadTokens(); // Refresh tokens list
            loadDashboardStats(); // Refresh stats
            addRecentActivity('Token deleted successfully', 'success');
        } else {
            showAlert('Error deleting token: ' + data.message);
            addRecentActivity('Failed to delete token', 'error');
        }
    } catch (error) {
        console.error('Error deleting token:', error);
        showAlert('Network error. Please try again.');
        addRecentActivity('Network error while deleting token', 'error');
    }
}

// Force logout session
async function forceLogout(sessionId) {
    if (!confirm('Are you sure you want to force logout this session?')) {
        return;
    }

    try {
        const response = await fetch(`/api/admin/sessions/${sessionId}/force-logout`, {
            method: 'POST'
        });

        const data = await response.json();

        if (data.success) {
            // Clear countdown for this session
            if (sessionCountdownIntervals.has(sessionId)) {
                clearInterval(sessionCountdownIntervals.get(sessionId));
                sessionCountdownIntervals.delete(sessionId);
            }

            loadSessions(); // Refresh sessions list
            loadDashboardStats(); // Refresh stats
            addRecentActivity('Session force logout executed', 'warning');
        } else {
            showAlert('Error forcing logout: ' + data.message);
            addRecentActivity('Failed to force logout session', 'error');
        }
    } catch (error) {
        console.error('Error forcing logout:', error);
        showAlert('Network error. Please try again.');
        addRecentActivity('Network error while forcing logout', 'error');
    }
}

// Toggle auto-delete expired tokens
async function toggleAutoDelete() {
    try {
        const response = await fetch('/api/admin/auto-delete-expired', {
            method: 'PATCH'
        });

        const data = await response.json();

        if (data.success) {
            autoDeleteEnabled = data.autoDeleteEnabled;
            updateAutoDeleteStatus();
            loadTokens(); // Refresh tokens list
            addRecentActivity(`Auto-delete ${autoDeleteEnabled ? 'enabled' : 'disabled'}`, 'info');
        } else {
            showAlert('Error toggling auto-delete: ' + data.message);
            addRecentActivity('Failed to toggle auto-delete', 'error');
        }
    } catch (error) {
        console.error('Error toggling auto-delete:', error);
        showAlert('Network error. Please try again.');
        addRecentActivity('Network error while toggling auto-delete', 'error');
    }
}

// Update auto-delete status display
function updateAutoDeleteStatus() {
    const statusElement = document.getElementById('autoDeleteStatus');
    statusElement.textContent = autoDeleteEnabled ? 'ON' : 'OFF';

    const button = document.getElementById('toggleAutoDelete');
    if (autoDeleteEnabled) {
        button.classList.remove('btn-warning');
        button.classList.add('btn-success');
    } else {
        button.classList.remove('btn-success');
        button.classList.add('btn-warning');
    }
}

// Load initial data
function loadInitialData() {
    loadUsers();
    loadTokens();
    loadSessions();
}

// Real-time event handlers
function handleLoginAttempt(data) {
    const status = data.success ? 'success' : 'error';
    const message = `Login attempt by ${data.username} from ${data.ip} - ${data.success ? 'Success' : 'Failed'}`;
    addRecentActivity(message, status);

    if (currentSection === 'dashboard') {
        animateRequestFlow('login', data.success);
    }
}

function handleTokenVerification(data) {
    const status = data.success ? 'success' : 'error';
    const message = `Token verification for ${data.username || 'Unknown'} - ${data.success ? 'Valid' : 'Invalid'}`;
    addRecentActivity(message, status);

    if (currentSection === 'dashboard') {
        animateRequestFlow('token', data.success);
    }

    // Refresh tokens if on tokens page
    if (currentSection === 'tokens') {
        loadTokens();
    }
}

function handleSessionCreated(data) {
    addRecentActivity(`New session created for ${data.username}`, 'success');
    loadDashboardStats();

    if (currentSection === 'sessions') {
        loadSessions();
    }
}

function handleUserLogout(data) {
    addRecentActivity(`User ${data.username} logged out`, 'info');
    loadDashboardStats();

    if (currentSection === 'sessions') {
        loadSessions();
    }
}

function handleSecurityAlert(data) {
    let message = '';

    if (data.type === 'MULTIPLE_FAILED_LOGINS') {
        message = `⚠ Security Alert: ${data.username} has ${data.attempts} failed login attempts from ${data.lastIP}`;
    } else if (data.type === 'MULTIPLE_FAILED_TOKENS') {
        message = `⚠ Security Alert: ${data.username} is attempting unauthorized access with invalid tokens`;
    }

    showAlert(message);
    addRecentActivity(message, 'warning');
}

function handleVirtualTokenGenerated(data) {
    addRecentActivity(`Virtual token generated for device ${data.device_id}`, 'info');

    if (currentSection === 'tokens') {
        loadTokens();
    }
}

function handleSessionForceLogout(data) {
    addRecentActivity(`Session force logout executed`, 'warning');

    if (currentSection === 'sessions') {
        loadSessions();
    }
}

function handleTokenExpired(data) {
    addRecentActivity(`Token expired for device ${data.device_id}`, 'warning');

    if (currentSection === 'tokens') {
        loadTokens();
    }
    loadDashboardStats();
}

// Add recent activity
function addRecentActivity(message, type = 'info') {
    const activityContainer = document.getElementById('recentActivity');

    // Remove "No recent activity" message if present
    const emptyMessage = activityContainer.querySelector('.text-center');
    if (emptyMessage) {
        emptyMessage.remove();
    }

    const activityItem = document.createElement('div');
    activityItem.className = `flex items-start p-4 rounded-xl ${getActivityClass(type)} border-l-4 ${getActivityBorderClass(type)}`;

    const icon = getActivityIcon(type);
    const timestamp = new Date().toLocaleTimeString();

    activityItem.innerHTML = `
        <div class="flex-shrink-0 mt-1">
            ${icon}
        </div>
        <div class="ml-3 flex-1">
            <p class="text-sm font-medium text-gray-900">${message}</p>
            <p class="text-xs text-gray-500 mt-1">${timestamp}</p>
        </div>
    `;

    // Add to top of list
    activityContainer.insertBefore(activityItem, activityContainer.firstChild);

    // Keep only last 8 activities
    while (activityContainer.children.length > 8) {
        activityContainer.removeChild(activityContainer.lastChild);
    }
}

// Animate request flow on live map
function animateRequestFlow(type, success) {
    const liveMap = document.getElementById('liveMap');

    // Create animated elements
    const sourceIcon = document.createElement('div');
    sourceIcon.className = 'floating-icon w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-xs font-semibold shadow-lg';
    sourceIcon.textContent = type === 'login' ? '👤' : '📱';
    sourceIcon.style.left = '15%';
    sourceIcon.style.top = '50%';

    const targetIcon = document.createElement('div');
    targetIcon.className = 'floating-icon w-8 h-8 bg-gray-600 rounded-full flex items-center justify-center text-white text-xs font-semibold shadow-lg';
    targetIcon.textContent = '⚡';
    targetIcon.style.right = '15%';
    targetIcon.style.top = '50%';

    const line = document.createElement('div');
    line.className = `connection-line ${success ? 'bg-green-500' : 'bg-red-500'} shadow-md`;
    line.style.left = '23%';
    line.style.top = '50%';
    line.style.width = '54%';
    line.style.transform = 'scaleX(0)';

    liveMap.appendChild(sourceIcon);
    liveMap.appendChild(targetIcon);
    liveMap.appendChild(line);

    // Animate the line
    setTimeout(() => {
        line.style.transform = 'scaleX(1)';
    }, 100);

    // Remove after delay
    setTimeout(() => {
        if (sourceIcon.parentNode) sourceIcon.parentNode.removeChild(sourceIcon);
        if (targetIcon.parentNode) targetIcon.parentNode.removeChild(targetIcon);
        if (line.parentNode) line.parentNode.removeChild(line);
    }, 3000);
}

// Show security alert modal
function showAlert(message) {
    document.getElementById('alertMessage').textContent = message;
    document.getElementById('alertModal').classList.remove('hidden');
}

// Close alert modal
function closeAlert() {
    document.getElementById('alertModal').classList.add('hidden');
}

// Admin logout
async function logout() {
    try {
        // Clear all intervals before logout
        clearAllTokenCountdowns();
        clearAllSessionCountdowns();

        await fetch('/api/admin/logout', {
            method: 'POST'
        });
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        window.location.href = '/admin/login';
    }
}

// Utility functions
function formatDate(dateString) {
    return new Date(dateString).toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function formatDateShort(dateString) {
    return new Date(dateString).toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function formatTime(seconds) {
    if (seconds <= 0) return '00:00';
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

function getStatusClass(status) {
    switch (status) {
        case 'ACTIVE':
            return 'status-active';
        case 'USED':
            return 'status-used';
        case 'EXPIRED':
            return 'status-expired';
        case 'PENDING':
            return 'status-pending';
        default:
            return 'status-pending';
    }
}

function getMobileStatusBadge(status) {
    switch (status) {
        case 'ACTIVE':
            return '<span class="status-badge status-active">ACTIVE</span>';
        case 'USED':
            return '<span class="status-badge status-used">USED</span>';
        case 'EXPIRED':
            return '<span class="status-badge status-expired">EXPIRED</span>';
        case 'PENDING':
            return '<span class="status-badge status-pending">PENDING</span>';
        default:
            return '<span class="status-badge status-pending">UNKNOWN</span>';
    }
}

function getActivityClass(type) {
    switch (type) {
        case 'success':
            return 'bg-green-50';
        case 'error':
            return 'bg-red-50';
        case 'warning':
            return 'bg-yellow-50';
        default:
            return 'bg-blue-50';
    }
}

function getActivityBorderClass(type) {
    switch (type) {
        case 'success':
            return 'border-green-400';
        case 'error':
            return 'border-red-400';
        case 'warning':
            return 'border-yellow-400';
        default:
            return 'border-blue-400';
    }
}

function getActivityIcon(type) {
    const iconClass = 'h-5 w-5';

    switch (type) {
        case 'success':
            return `<svg class="${iconClass} text-green-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>`;
        case 'error':
            return `<svg class="${iconClass} text-red-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path></svg>`;
        case 'warning':
            return `<svg class="${iconClass} text-yellow-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>`;
        default:
            return `<svg class="${iconClass} text-blue-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path></svg>`;
    }
}