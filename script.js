document.addEventListener('DOMContentLoaded', () => {
    const mobileBtn = document.getElementById('mobile-menu-btn');
    const sidebar = document.getElementById('sidebar');
    const contentArea = document.querySelector('.content-area');
    const themeToggle = document.getElementById('theme-toggle');

    // --- Theme Toggle Logic ---
    function updateThemeIcon(isDark) {
        if (!themeToggle) return;
        themeToggle.innerHTML = `<i data-lucide="${isDark ? 'sun' : 'moon'}"></i>`;
        if (window.lucide) {
            lucide.createIcons();
        }
    }

    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            document.body.classList.toggle('dark-theme');
            const isDark = document.body.classList.contains('dark-theme');
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
            updateThemeIcon(isDark);

            // Dispatch event for other scripts (e.g., re-rendering charts)
            window.dispatchEvent(new CustomEvent('themeChanged', { detail: { isDark } }));
        });
    }

    // Initialize Theme on Load
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
        document.body.classList.add('dark-theme');
        updateThemeIcon(true);
    }


    if (mobileBtn) {
        mobileBtn.addEventListener('click', () => {
            sidebar.classList.toggle('active');

            // Optional: Change icon to 'X' when open
            const icon = mobileBtn.querySelector('i');
            if (sidebar.classList.contains('active')) {
                // We can let Lucide re-render or just toggle class
            }
        });
    }

    // Close sidebar when clicking outside (on all views now that it's auto-hide everywhere)
    document.addEventListener('click', (e) => {
        if (mobileBtn && sidebar && !sidebar.contains(e.target) && !mobileBtn.contains(e.target) && sidebar.classList.contains('active')) {
            sidebar.classList.remove('active');
        }
    });

    // --- Smooth Scrolling ---
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;

            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                // Adjust for fixed header
                const headerOffset = 80;
                const elementPosition = targetElement.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

                window.scrollTo({
                    top: offsetPosition,
                    behavior: "smooth"
                });

                // Close sidebar after selection (all view)
                if (sidebar) {
                    sidebar.classList.remove('active');
                }
            }
        });
    });

    // --- Sidebar Filter Interactions (Demo) ---
    const sizeBtns = document.querySelectorAll('.size-selector button');
    sizeBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active from all siblings
            sizeBtns.forEach(b => b.classList.remove('active'));
            // Add to clicked
            btn.classList.add('active');
        });
    });

    // --- Sidebar Accordion Menu ---
    const menuToggles = document.querySelectorAll('.menu-toggle');

    menuToggles.forEach(toggle => {
        toggle.addEventListener('click', () => {
            // Toggle active class on button (for arrow rotation)
            toggle.classList.toggle('active');

            // Toggle max-height of the next sibling (submenu)
            const submenu = toggle.nextElementSibling;
            if (submenu.style.maxHeight) {
                submenu.style.maxHeight = null;
            } else {
                submenu.style.maxHeight = submenu.scrollHeight + "px";
            }
        });
    });

    // Initialize Lucide Icons again in case dynamic stuff needed it (though script tag handles initial load)
    if (window.lucide) {
        lucide.createIcons();
    }

    // Check Login State
    const userIconLink = document.querySelector('a[href="login.html"]');
    if (userIconLink && localStorage.getItem('isLoggedIn') === 'true') {
        const role = localStorage.getItem('userRole');
        userIconLink.href = (role === 'admin') ? 'admin.html' : 'dashboard.html';
    }

    // Update Dashboard Info
    const userNameDisplay = document.getElementById('userNameDisplay');
    const userAvatar = document.getElementById('userAvatar');
    const storedName = localStorage.getItem('userName');

    if (userNameDisplay && storedName) {
        userNameDisplay.textContent = storedName;
        if (userAvatar) {
            userAvatar.textContent = storedName.split(' ').map(n => n[0]).join('').toUpperCase().substring(0, 2);
        }
    }

    // --- Advanced Security Engine ---
    class SecurityEngine {
        constructor() {
            this.requestCounts = {};
            this.CSRF_TOKEN = this._generateToken();
            this.DOS_THRESHOLD = 10; // Max actions per 10 seconds
            this.TIME_WINDOW = 10000;
        }

        _generateToken() {
            return Math.random().toString(36).substring(2) + Date.now().toString(36);
        }

        // 1. XSS Protection: Advanced Sanitization
        sanitize(str) {
            if (typeof str !== 'string') return str;
            const doc = new DOMParser().parseFromString(str, 'text/html');
            const sanitized = doc.body.textContent || "";
            return sanitized.replace(/[&<>"']/g, m => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            }[m])).trim();
        }

        // 2. SQLi Protection: Pattern Matching
        detectSQLi(str) {
            const patterns = [
                /UNION\s+SELECT/i,
                /SELECT\s+.*\s+FROM/i,
                /INSERT\s+INTO/i,
                /DROP\s+TABLE/i,
                /UPDATE\s+.*\s+SET/i,
                /--/i,
                /;/i,
                /'\s*OR\s*'/i
            ];
            return patterns.some(pattern => pattern.test(str));
        }

        // 3. DoS Protection: Rate Limiting
        isRateLimited(actionId) {
            const now = Date.now();
            if (!this.requestCounts[actionId]) {
                this.requestCounts[actionId] = [];
            }
            this.requestCounts[actionId] = this.requestCounts[actionId].filter(t => now - t < this.TIME_WINDOW);

            if (this.requestCounts[actionId].length >= this.DOS_THRESHOLD) {
                window.logActivity('DoS Detected', `Rate limit exceeded for action: ${actionId}`);
                return true;
            }
            this.requestCounts[actionId].push(now);
            return false;
        }

        // 4. CSRF Protection: Token Management
        getCsrfToken() {
            return this.CSRF_TOKEN;
        }

        validateCsrf(token) {
            return token === this.CSRF_TOKEN;
        }
    }

    window.security = new SecurityEngine();

    // Utility: Global Input Handler
    function secureInput(raw) {
        if (security.detectSQLi(raw)) {
            window.logActivity('SQLi Attempt', `Blocked input: ${raw}`);
            alert('Security Alert: Malicious patterns detected.');
            return "";
        }
        return security.sanitize(raw);
    }

    // --- Original Sanitization Helper (Legacy Support) ---
    function sanitizeInput(str) {
        return secureInput(str);
    }

    function isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    // --- Session Handling & Access Control ---
    const SESSION_TIMEOUT_MS = 15 * 60 * 1000; // 15 Minutes

    function updateSession() {
        if (localStorage.getItem('isLoggedIn') === 'true') {
            localStorage.setItem('sessionExpiry', Date.now() + SESSION_TIMEOUT_MS);
        }
    }

    function checkSession() {
        const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';
        const expiry = parseInt(localStorage.getItem('sessionExpiry') || '0');
        const currentPage = window.location.pathname.split('/').pop();

        if (isLoggedIn) {
            // Check if session expired
            if (Date.now() > expiry) {
                alert('Session expired. Please login again.');
                performLogout();
                return;
            }
            // If logged in, only auto-redirect if on the correct port for the role
            if (currentPage === 'login.html' || currentPage === 'signup.html') {
                const role = localStorage.getItem('userRole');
                const port = window.location.port;

                if (role === 'admin' && port === '8001') {
                    window.location.href = 'admin.html';
                } else if (role === 'user' && port === '8000') {
                    window.location.href = 'dashboard.html';
                }
                // If mismatch (e.g., Admin session on User port), stay on login page
            }
            // Update expiry on every interaction (activity track)
            updateSession();
        } else {
            // If NOT logged in, don't allow protected pages
            const protectedPages = ['index.html', 'dashboard.html', 'admin.html', 'checkout.html', ''];
            if (protectedPages.includes(currentPage)) {
                window.location.href = 'login.html';
            }
        }
    }

    function performLogout() {
        logActivity('Logout', 'User logged out');
        localStorage.removeItem('isLoggedIn');
        localStorage.removeItem('userName');
        localStorage.removeItem('userRole');
        localStorage.removeItem('sessionExpiry');
        window.location.href = 'login.html';
    }

    // Logging Helper
    window.logActivity = function (action, details) {
        let logs = JSON.parse(localStorage.getItem('securityLogs') || '[]');
        logs.unshift({
            timestamp: new Date().toISOString(),
            action,
            details,
            user: localStorage.getItem('userName') || 'Guest'
        });
        // Keep only last 100 logs
        if (logs.length > 100) logs.pop();
        localStorage.setItem('securityLogs', JSON.stringify(logs));
    }

    // --- Dynamic Security Patching ---
    function patchSecurity() {
        // Inject CSRF Tokens into all forms
        document.querySelectorAll('form').forEach(form => {
            if (!form.querySelector('input[name="csrf_token"]')) {
                const tokenInput = document.createElement('input');
                tokenInput.type = 'hidden';
                tokenInput.name = 'csrf_token';
                tokenInput.value = security.getCsrfToken();
                form.appendChild(tokenInput);
            }
        });
    }

    // Run session check on load
    checkSession();
    patchSecurity();
    // Update session on clicks
    document.addEventListener('click', updateSession);

    // --- Suspicious Behavior Detection Logic ---
    const BRUTE_FORCE_THRESHOLD = 3;

    function checkSuspiciousBehavior(email) {
        let attempts = JSON.parse(localStorage.getItem('failedLoginAttempts') || '{}');
        let count = attempts[email] || 0;

        if (count >= BRUTE_FORCE_THRESHOLD) {
            logActivity('SECURITY ALERT', `Suspicious activity detected for ${email}. Potential brute-force.`);
            return true;
        }
        return false;
    }

    function recordFailure(email) {
        let attempts = JSON.parse(localStorage.getItem('failedLoginAttempts') || '{}');
        attempts[email] = (attempts[email] || 0) + 1;
        localStorage.setItem('failedLoginAttempts', JSON.stringify(attempts));
    }

    function clearFailures(email) {
        let attempts = JSON.parse(localStorage.getItem('failedLoginAttempts') || '{}');
        delete attempts[email];
        localStorage.setItem('failedLoginAttempts', JSON.stringify(attempts));
    }

    // --- Password Security Helpers ---
    async function hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function validatePassword(password) {
        const minLength = password.length >= 8;
        const hasUpper = /[A-Z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
        return minLength && hasUpper && hasNumber && hasSpecial;
    }

    // Handle Login Form
    const loginForm = document.getElementById('loginForm');
    const verifyForm = document.getElementById('verifyForm');

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // DoS Check
            if (security.isRateLimited('login_attempt')) {
                alert('Too many attempts. Please wait 10 seconds.');
                return;
            }

            const rawEmail = loginForm.querySelector('input[type="email"]').value;
            const password = loginForm.querySelector('input[type="password"]').value;
            const csrf = loginForm.querySelector('input[name="csrf_token"]')?.value;

            // CSRF Validation
            if (!security.validateCsrf(csrf)) {
                logActivity('CSRF Violation', 'Login form missing valid token');
                alert('Security Error: Invalid Session Token.');
                return;
            }

            // Sanitization & Validation
            const email = sanitizeInput(rawEmail);
            if (!isValidEmail(email)) {
                alert('Please enter a valid email address.');
                return;
            }

            // Get all users
            const users = JSON.parse(localStorage.getItem('registeredUsers') || '[]');

            // Hash the input password for comparison
            const hashedPassword = await hashPassword(password);

            // Brute Force Check
            if (checkSuspiciousBehavior(email)) {
                alert('Account temporarily locked due to multiple failed attempts. Please contact admin.');
                return;
            }

            // Find user (checking for both hashed and legacy plain text for demo stability)
            const user = users.find(u => u.email === email && (u.password === hashedPassword || u.password === password));

            if (user) {
                // Success - reset failures
                clearFailures(email);
                // Generate 2FA Code
                const code = Math.floor(100000 + Math.random() * 900000).toString();

                // Store temporarily
                sessionStorage.setItem('tempAuthCode', code);
                sessionStorage.setItem('tempUserEmail', email);

                // Simulate Sending Email
                console.log(`Sending 2FA to ${email}: ${code}`);
                alert(`Your 2FA Verification Code is: ${code}`);

                // Switch to Verify View
                loginForm.style.display = 'none';
                if (verifyForm) {
                    verifyForm.style.display = 'block';
                    // Focus on input
                    verifyForm.querySelector('input').focus();
                } else {
                    // Fallback if verifyForm missing
                    const input = prompt(`Enter the code sent to ${email} (Code: ${code})`);
                    if (input === code) {
                        logActivity('2FA Success', `Code verified for ${email}`);
                        completeLogin(user);
                    } else {
                        logActivity('2FA Failure', `Incorrect code entered for ${email}`);
                        recordFailure(email);
                        alert('Invalid Code');
                    }
                }

            } else {
                logActivity('Login Failure', `Invalid credentials for ${email}`);
                recordFailure(email);
                alert('Invalid email or password. Please try again.');
            }
        });
    }

    if (verifyForm) {
        verifyForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const inputCode = verifyForm.querySelector('input').value.trim();
            const validCode = sessionStorage.getItem('tempAuthCode');
            const email = sessionStorage.getItem('tempUserEmail');

            // Force Numeric Check
            if (!/^\d{6}$/.test(inputCode)) {
                logActivity('Input Validation', 'Invalid 2FA format entered');
                alert('Verification code must be exactly 6 digits.');
                return;
            }

            if (inputCode === validCode) {
                const users = JSON.parse(localStorage.getItem('registeredUsers') || '[]');
                const user = users.find(u => u.email === email);
                if (user) {
                    logActivity('2FA Success', `2FA verified for ${email}`);
                    clearFailures(email);
                    completeLogin(user);
                }
            } else {
                logActivity('2FA Failure', `Incorrect 2FA for ${email}`);
                recordFailure(email);
                alert('Invalid Verification Code. Please try again.');
            }
        });
    }

    function completeLogin(user) {
        const resolvedRole = user.role || 'user';
        logActivity('Login Success', `User logged in as ${resolvedRole}`);

        localStorage.setItem('isLoggedIn', 'true');
        localStorage.setItem('userName', user.name);
        localStorage.setItem('userRole', resolvedRole);
        localStorage.setItem('sessionExpiry', Date.now() + SESSION_TIMEOUT_MS);

        showNotification('Login Successful', `Welcome back, ${user.name}!`);

        // Clean up temp
        sessionStorage.removeItem('tempAuthCode');
        sessionStorage.removeItem('tempUserEmail');

        setTimeout(() => {
            if (resolvedRole === 'admin') {
                window.location.href = 'admin.html';
            } else {
                window.location.href = 'dashboard.html';
            }
        }, 1500);
    }

    // Handle Signup Form
    const signupForm = document.getElementById('signupForm');
    if (signupForm) {
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // DoS Check
            if (security.isRateLimited('signup_attempt')) {
                alert('Rate limit exceeded. Try again later.');
                return;
            }

            const rawName = signupForm.querySelector('input[type="text"]').value;
            const rawEmail = signupForm.querySelector('input[type="email"]').value;
            const password = signupForm.querySelector('input[type="password"]').value;
            const roleSelect = signupForm.querySelector('select');
            const role = roleSelect ? roleSelect.value : 'user';

            // Sanitization
            const name = sanitizeInput(rawName);
            const email = sanitizeInput(rawEmail);

            // Validation
            if (name.length < 2) {
                alert('Please enter a valid name.');
                return;
            }
            if (!isValidEmail(email)) {
                alert('Please enter a valid email address.');
                return;
            }

            // Validate Password Policy
            if (!validatePassword(password)) {
                alert('Password does not meet the requirements:\n- 8+ characters\n- One uppercase letter\n- One number\n- One special character');
                return;
            }

            // Get existing users (our 'Local Database')
            let users = JSON.parse(localStorage.getItem('registeredUsers') || '[]');

            // Database Limit Check (150 Users)
            if (users.length >= 150) {
                alert('Database Limit Reached (Max 150 users). Registration is currently closed.');
                return;
            }

            // Check if user already exists
            if (users.some(u => u.email === email)) {
                alert('This email is already registered. Please login instead.');
                return;
            }

            // Hash the password before saving
            const hashedPassword = await hashPassword(password);

            // Add new user to 'Database'
            users.push({
                name,
                email,
                password: hashedPassword, // Store Hash
                role, // Save Role
                joinedAt: new Date().toISOString()
            });
            localStorage.setItem('registeredUsers', JSON.stringify(users));

            logActivity('Signup', `New user registered: ${email} (${role})`);

            // Auto Login after signup? No, let's force login which forces 2FA flow for better security demo
            showNotification('Registration Successful', `Account created as ${role.toUpperCase()}. Please Login.`);

            setTimeout(() => {
                window.location.href = 'login.html';
            }, 2000);
        });
    }

    // --- Contact Form Logic ---
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(contactForm);

            // Sanitize all inputs
            const name = sanitizeInput(formData.get('name'));
            const email = sanitizeInput(formData.get('email'));
            const subject = sanitizeInput(formData.get('subject'));
            const message = sanitizeInput(formData.get('message'));

            if (!isValidEmail(email)) {
                alert('Please provide a valid email.');
                return;
            }

            showNotification('Query Received', `Info sent to 7984974394 via SMS. Thank you, ${name}!`);

            contactForm.reset();
        });
    }
});

// --- Utility Functions ---
function showNotification(title, message) {
    // Create container if it doesn't exist
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    // Create toast
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
        <i data-lucide="check-circle"></i>
        <div class="toast-content">
            <p>${title}</p>
            <span>${message}</span>
        </div>
    `;

    container.appendChild(toast);

    // Process icons
    if (window.lucide) lucide.createIcons();

    // Show toast
    setTimeout(() => toast.classList.add('show'), 100);

    // Remove toast
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 400);
    }, 4000);
}

// --- Dynamic Product Rendering ---
const products = {
    bestSellers: [
        { title: "Premium Cotton Heavy Weight Tee", image: "https://i.pinimg.com/236x/2d/ca/0a/2dca0ac38157e691cc2cd9133950c8c0.jpg", brand: "ZARA", price: 999, oldPrice: 1499 },
        { title: "Air Jordan 1 Retro High", image: "assets/jordan-retro-high.jpg", brand: "NIKE", price: 4999, oldPrice: 7999 },
        { title: "Distressed Leather Biker Jacket", image: "https://i.pinimg.com/236x/fb/fc/5c/fbfc5c3ef504695687973ca4758f8ef4.jpg", brand: "AMIRI", price: 6500, oldPrice: 8999 },
        { title: "Logo-Embroidered Cotton Cap", image: "https://i.pinimg.com/236x/4d/df/59/4ddf5937121770b94f6078abdb50b477.jpg", brand: "BALENCIAGA", price: 899, oldPrice: 1299 }
    ],
    tees: [
        { title: "BONES LONG SLEEVE TEE", image: "https://amiri.com/cdn/shop/files/226_PS26_Men_Tops_Tee__AMTOJR1116-901_BONES_20LS_20TEE_Camo_088_1b133e8257c94ed0a3aa46ac9f024c02.jpg?v=1762847297&width=550", brand: "AMIRI", price: 66140 },
        { title: "BONES LONG SLEEVE TEE - BLACK", image: "https://amiri.com/cdn/shop/files/48_PS26_Men_Tops_LS_20Tee_BONES_AMTOJR1032-001_BONES_20LS_20TEE_Black_167_842c641db2e2431aa7d97d3f3a9a8c33.jpg?v=1762193916&width=550", brand: "AMIRI", price: 66140 },
        { title: "BONES LONG SLEEVE TEE - IVORY", image: "https://amiri.com/cdn/shop/files/47_PS26_Men_Tops_LS_20Tee_BONES_AMTOJR1032-127_BONES_20LS_20TEE_Ivory_047_de3f7ae399ba4db1ad14c8be4fd42bf5.jpg?v=1762193911&width=550", brand: "AMIRI", price: 66140 },
        { title: "SKATE TEE AMIRI SPORT", image: "https://amiri.com/cdn/shop/files/227_PS26_Men_Tops_Tee__AMTOJR1033-080_SKATE_20TEE_20AMIRI_20SPORT_20OVERSIZED_20TEE_Stone_095_1687baeba99f400d877c69228d31aadc.jpg?v=1762231872&width=550", brand: "AMIRI", price: 46970 },
        { title: "AMIRI SPORT OVERSIZED TEE", image: "https://amiri.com/cdn/shop/files/21_PS26_Men_Tops_Tee_SPORT_AMTOJR1033-584_AMIRI_20SPORT_20OVERSIZED_20TEE_Aged_20Port-575_REPAIRED_20BOOT_20CUT_20JEAN_Mist_20Indigo_040_0963d812d8654491aa4bf06f0f8af8a1.jpg?v=1762193948&width=550", brand: "AMIRI", price: 46970 },
        { title: "AMIRI SPORT TEE - BLACK", image: "https://amiri.com/cdn/shop/files/22_PS26_Men_Tops_Tee_SPORT_AMTOJR1033-001_AMIRI_20SPORT_20OVERSIZED_20TEE_Black_043_8b42092aff794f3abc55206154348faf.jpg?v=1762193938&width=550", brand: "AMIRI", price: 46970 },
        { title: "CAMO OVERSIZED TEE", image: "https://amiri.com/cdn/shop/files/45_PS26_Men_Tops_Tee_CAMO_AMTOKN1016-310_CAMO_20OS_20TEE_Green_05aa6eb3e17f4a60a520a1b4650c3ba2.jpg?v=1762237009&width=550", brand: "AMIRI", price: 71890 },
        { title: "SPLICED OVERSIZED MESH TEE", image: "https://amiri.com/cdn/shop/files/AMTOJR1011-610_SPLICED_20OVERSIZED_20MESH_20TEE_RED_4e7c28cade0048ae90473aca96f76255.jpg?v=1762992506&width=550", brand: "AMIRI", price: 46970 },
        { title: "SPLICED OVERSIZED TEE - BLACK", image: "https://amiri.com/cdn/shop/files/49_PS26_Men_Tops_Tee_SPLICE_AMTOJR1043-001_SPLICED_20OVERSIZED_20TEE_Black_045_4e6d9dd78f08471c89bdb1dba05c99d2.jpg?v=1762193937&width=550", brand: "AMIRI", price: 43140 },
        { title: "AMIRI EAGLE OVERSIZED TEE", image: "https://amiri.com/cdn/shop/files/57_PS26_Men_Tops_Tee_EAGLE_AMTOJR1024-901_AMIRI_20EAGLE_20OVERSIZED_20TEE_Camo_052_ebe7217e33f040528fea5b53b6714646.jpg?v=1762193952&width=550", brand: "AMIRI", price: 56550 }
    ],
    jeans: [
        { title: "WAXED STRAIGHT-LEG JEANS", image: "https://static.zara.net/assets/public/6c39/dfaf/0f2b4fbdb74d/10528fee872c/00840392400-a5/00840392400-a5.jpg?ts=1764934851597&w=326", brand: "ZARA", price: 5950 },
        { title: "FLOCKED STRAIGHT-LEG JEANS", image: "https://static.zara.net/assets/public/d142/4c29/68be423e862e/acb71c20aeef/05585314700-a4/05585314700-a4.jpg?ts=1766394176705&w=326", brand: "ZARA", price: 9550 },
        { title: "ABSTRACT JACQUARD STRAIGHT-LEG JEANS", image: "https://static.zara.net/assets/public/dcbd/10b6/0c3443cc8f2e/ec0c2c0d183c/00840398800-p/00840398800-p.jpg?ts=1764934863851&w=326", brand: "ZARA", price: 5950 },
        { title: "STRAIGHT-LEG JEANS WITH STUDS", image: "https://static.zara.net/assets/public/1a16/8641/53c3427d897a/8d06640f179f/04048320800-p/04048320800-p.jpg?ts=1764936672693&w=326", brand: "ZARA", price: 4950 },
        { title: "STRAIGHT FIT JEANS", image: "https://static.zara.net/assets/public/1502/3434/b98f468684d6/d7b6720572fa/00840315251-a4/00840315251-a4.jpg?ts=1758881042151&w=326", brand: "ZARA", price: 2950 },
        { title: "SLIM FIT JEANS", image: "https://static.zara.net/assets/public/debd/6577/d7e243a3a121/6c41e3b34a0e/05575344809-p/05575344809-p.jpg?ts=1761840468713&w=326", brand: "ZARA", price: 2950 },
        { title: "WIDE BELL BOTTOM FIT JEANS", image: "https://static.zara.net/assets/public/4090/adb5/4bea4486896d/74c8bb89bdab/06688321427-a4/06688321427-a4.jpg?ts=1753196796987&w=326", brand: "ZARA", price: 4950 },
        { title: "REGULAR STRAIGHT FIT JEANS", image: "https://static.zara.net/assets/public/7831/1d7a/a07143d79944/3f25eea86d90/04048321800-p/04048321800-p.jpg?ts=1759832910566&w=326", brand: "ZARA", price: 2950 },
        { title: "FLARE FIT JEANS", image: "https://static.zara.net/assets/public/cdd2/1a06/831d43c29ce2/1d1db4257d54/00840353802-a4/00840353802-a4.jpg?ts=1754648339681&w=326", brand: "ZARA", price: 4950 },
        { title: "WAXED-EFFECT BAGGY FIT JEANS", image: "https://static.zara.net/assets/public/0e41/256a/37394309a0aa/3b61c3b4c101/09794380822-a3/09794380822-a3.jpg?ts=1762869469976&w=326", brand: "ZARA", price: 4950 }
    ],
    jackets: [
        { title: "LEATHER EFFECT BIKER JACKET", image: "https://static.zara.net/assets/public/4fc4/b8a7/ea9740009cea/1b2a9c871903/08491421800-a1/08491421800-a1.jpg?ts=1756972856810&w=342", brand: "ZARA", price: 5950 },
        { title: "HOODED LEATHER EFFECT JACKET", image: "https://static.zara.net/assets/public/d985/6ccb/22554653aa99/4490b704b422/03945401500-a1/03945401500-a1.jpg?ts=1756456949419&w=428", brand: "ZARA", price: 5950 },
        { title: "RIBBED BOXY FIT JACKET", image: "https://static.zara.net/assets/public/b10f/e59f/85ff4b72bdd6/450edf28dff8/01437366800-a1/01437366800-a1.jpg?ts=1764325415699&w=342", brand: "ZARA", price: 7550 },
        { title: "LEATHER EFFECT JACKET", image: "https://static.zara.net/assets/public/739e/b2cf/0ea44d3986f8/4f966f48276a/00155752800-a1/00155752800-a1.jpg?ts=1764325396554&w=342", brand: "ZARA", price: 7550 },
        { title: "ZIP-UP WOOL EFFECT JACKET", image: "https://static.zara.net/assets/public/62ce/2c67/b85d4f6a9fdf/2b268a9fb86e/image-web-6c6b144b-ddae-4961-b5c4-be5269cb29e9-default/image-web-6c6b144b-ddae-4961-b5c4-be5269cb29e9-default.jpg?ts=1762167267440&w=342", brand: "ZARA", price: 5950 },
        { title: "LEATHER EFFECT BOMBER JACKET", image: "https://static.zara.net/assets/public/90c9/53c4/4253420ea67a/1a679299a88a/04027400753-a1/04027400753-a1.jpg?ts=1765818328502&w=342", brand: "ZARA", price: 4950 },
        { title: "COMBINED QUILTED JACKET", image: "https://static.zara.net/assets/public/9f83/6b76/0d104bc788f9/262262b38ed3/image-web-6c987c2a-5ce3-4540-bce7-33a4beba7322-default/image-web-6c987c2a-5ce3-4540-bce7-33a4beba7322-default.jpg?ts=1762278866356&w=342", brand: "ZARA", price: 4350 },
        { title: "CONTRAST PADDED JACKET", image: "https://static.zara.net/assets/public/7b1e/c5cf/b235407e8aee/ba7da5d4a9cd/08574800505-e1/08574800505-e1.jpg?ts=1759746873568&w=292", brand: "ZARA", price: 4350 },
        { title: "DOUBLE-FACED LEATHER EFFECT JACKET", image: "https://static.zara.net/assets/public/b3d4/aa74/c86e448abe58/eb7a5bf7009b/03548301800-a1/03548301800-a1.jpg?ts=1764772839387&w=342", brand: "ZARA", price: 10950 },
        { title: "CROPPED FIT FAUX SUEDE JACKET", image: "https://static.zara.net/assets/public/7b32/1c62/fd3d4b09bb30/438726fbb49b/08281152800-a1/08281152800-a1.jpg?ts=1764775347371&w=342", brand: "ZARA", price: 7550 }
    ],
    hoodies: [
        { title: "Men's Contrast Stitching Hoodie", image: "https://i.pinimg.com/736x/48/ef/be/48efbeead4c64eddb27ffd53cf690d8c.jpg", brand: "VENS" },
        { title: "VFIVE UNFOUR 350gsm Thick Hoodie", image: "https://i.pinimg.com/736x/20/67/cf/2067cf314c0c60f943273105f91f5042.jpg", brand: "VFIVE" },
        { title: "Manfinity EMRG Loose Fit Hoodie", image: "https://i.pinimg.com/736x/23/f5/e7/23f5e7f197ce39c77b5eba2c25ab9538.jpg", brand: "MANFINITY" },
        { title: "Authentic Levi's Hoodie Grey", image: "https://i.pinimg.com/736x/2b/37/20/2b37209438f4abebcc8133812b7c5406.jpg", brand: "LEVI'S" },
        { title: "Men's Black Clearance Hoodie", image: "https://i.pinimg.com/736x/67/15/99/671599d4857ddc764d91dbefb3932df0.jpg", brand: "NIKE" },
        { title: "Riolio Corduroy Sweatshirt", image: "https://i.pinimg.com/736x/90/b6/03/90b603ec428cfcb5a5d4dff7bea67601.jpg", brand: "RIOLIO" },
        { title: "Letter Print Long Sleeve Sweatshirt", image: "https://i.pinimg.com/736x/fd/2d/fe/fd2dfeea940fc98f799c42e0ee03cb9a.jpg", brand: "STUSSY" },
        { title: "Porsche Sport Sweatshirt Blue", image: "https://i.pinimg.com/736x/7e/ee/49/7eee49d3dd7233731d0d6309fe0b9dd8.jpg", brand: "PORSCHE" },
        { title: "Geometric Pattern Crewneck", image: "https://i.pinimg.com/736x/ad/57/b4/ad57b41b49356b327a9c38f689c9d3f6.jpg", brand: "ZARA" },
        { title: "Y2K Star Pattern Sweater", image: "https://i.pinimg.com/736x/9a/f1/b7/9af1b7af7bf66153f9a17c3288423762.jpg", brand: "Y2K" }
    ],
    shoes: [
        { title: "Air Jordan 1 Retro High", image: "assets/jordan-retro-high.jpg", brand: "NIKE" },
        { title: "Business Casual Oxford Slip-On", image: "https://i.pinimg.com/236x/49/52/59/495259ae7b43d93d8f3307029c8c560d.jpg", brand: "CLARKS" },
        { title: "Revolve Fall Pick Boots", image: "https://i.pinimg.com/236x/b7/9d/49/b79d49a0e128ab2a81dca8fb07d6cc28.jpg", brand: "REVOLVE" },
        { title: "Prada Platform Loafers Black", image: "https://i.pinimg.com/236x/af/50/0a/af500afa576fd3606f37493155f6e6b6.jpg", brand: "PRADA" },
        { title: "High Street Collection Sneaker", image: "https://i.pinimg.com/236x/24/e3/df/24e3df1785da7bf608b68453d4730f3e.jpg", brand: "AXEL" },
        { title: "Fall 2021 Shoe Trend Leather", image: "https://i.pinimg.com/236x/3d/75/8e/3d758e8cd34c24791c1b0ef362cb5365.jpg", brand: "GUCCI" },
        { title: "Vintage Thick Sole Formal Shoes", image: "https://i.pinimg.com/236x/29/ef/d0/29efd085f7c1de7b35a39c5bf50f2a0f.jpg", brand: "DOCS" },
        { title: "Adidas Samba OG", image: "https://i.pinimg.com/236x/64/43/e0/6443e089f7b23d0a45aee62b30e90dc0.jpg", brand: "ADIDAS" },
        { title: "Kith New Balance 2002r Pistachio", image: "https://i.pinimg.com/236x/9d/d7/09/9dd7096e13df497139974c56d7d855fc.jpg", brand: "NEW BALANCE" },
        { title: "Axel Arigato Crafted Sneakers", image: "https://i.pinimg.com/236x/62/55/34/6255343048c24b2357fd92a0c67c7ec0.jpg", brand: "AXEL ARIGATO" },
        { title: "Air Jordan 4 Retro Royalty", image: "https://i.pinimg.com/236x/ca/e0/44/cae044e42e074086cf562c738d1eb51c.jpg", brand: "JORDAN" }
    ],
    accessories: [
        { title: "Designer Rings Jewelry", image: "https://i.pinimg.com/236x/ae/eb/60/aeeb609f2d6c85c700704d5c18a940be.jpg", brand: "KINTATTOO" },
        { title: "LA Dodgers Fitted Cap", image: "https://i.pinimg.com/236x/4d/df/59/4ddf5937121770b94f6078abdb50b477.jpg", brand: "NEW ERA" },
        { title: "Bikers Sports Sunglasses", image: "https://i.pinimg.com/236x/84/42/22/84422245dcc8f1c6efd5a36f37e61705.jpg", brand: "OAKLEY" },
        { title: "Irregular Square Reading Glasses", image: "https://i.pinimg.com/236x/84/e9/b4/84e9b46b45cc28e3f8c1326893c8eb58.jpg", brand: "KOCOLIOR" },
        { title: "Rimless Diamond Cutting Glasses", image: "https://i.pinimg.com/236x/f8/c9/6d/f8c96d5b61f6b2e3ec58846911fc46f4.jpg", brand: "REVEN JATE" },
        { title: "Stone Island Inspired Beanie", image: "https://i.pinimg.com/236x/14/b1/cf/14b1cfb1ebe51717dcba12d6eb9daf64.jpg", brand: "STONE ISLAND" },
        { title: "Prada Rectangle Sunglasses", image: "https://i.pinimg.com/236x/f9/5f/4f/f95f4fc23da08d67061d6c87b90eecf5.jpg", brand: "PRADA" },
        { title: "Futuristic Rings Tech Jewelry", image: "https://i.pinimg.com/236x/10/cf/2a/10cf2a40a13ce25de76b71db66dd9268.jpg", brand: "POSTHUMAN" },
        { title: "Zara Men's Leather Belt", image: "https://i.pinimg.com/236x/37/cc/78/37cc780e522483789baae3ef48104b57.jpg", brand: "ZARA" },
        { title: "High-Style Wardrobe Essentials", image: "https://i.pinimg.com/236x/b2/4e/bb/b24ebb5b9aee5469b674ee0db7ea1a40.jpg", brand: "GENERIC" },
        { title: "Dark Angel Wings Choker", image: "https://i.pinimg.com/236x/d2/11/a1/d211a10292b0049c75ae548c5ba8b5b8.jpg", brand: "GOTHIC" },
        { title: "Star Buckle PU Belt", image: "https://i.pinimg.com/236x/28/84/da/2884da1227f03af5bf128d0816bf1a95.jpg", brand: "HUIFACAI" },
        { title: "Luxury Watch Collection", image: "https://i.pinimg.com/236x/f4/a8/23/f4a82301b84869323f527ef81a99bfcc.jpg", brand: "ROLEX" },
        { title: "Faux Leather Skull Cap", image: "https://i.pinimg.com/236x/f1/7c/91/f17c91e2852795a3ec78313b95ce7f6b.jpg", brand: "BIKER" },
        { title: "Premium Navy Fedora Hat", image: "https://i.pinimg.com/236x/a8/69/69/a869696a57029121ec910e7378f29558.jpg", brand: "CASTOR" },
        { title: "Lock Key Pendant Necklace", image: "https://i.pinimg.com/236x/3a/d5/13/3ad513aad322ad5c5812778d4fa36fd9.jpg", brand: "TANYOYO" },
        { title: "Retro Steam Punk Glasses", image: "https://i.pinimg.com/236x/14/17/30/141730be19cd36692b4cd54ccc8d1173.jpg", brand: "TEL RETRO" },
        { title: "Louis Vuitton Accessories", image: "https://i.pinimg.com/236x/0f/1e/45/0f1e459b8661eb1416190f3b1964890a.jpg", brand: "LOUIS VUITTON" },
        { title: "RacerPods Y2K Tech Necklace", image: "https://i.pinimg.com/236x/36/70/6c/36706cba16d95fbd7f59797f255fb0ca.jpg", brand: "RACER" },
        { title: "Studded Bracelet Punk Cuff", image: "https://i.pinimg.com/236x/8e/f1/17/8ef117d13da6e863697b0255aeccd440.jpg", brand: "SONNYX" },
        { title: "Vintage Tees & Caps Drop", image: "https://i.pinimg.com/236x/c4/b3/2f/c4b32fc9ae9001f69e53d42f5f89b352.jpg", brand: "VINTAGE" },
        { title: "Lamb Wool Streetwear Hat", image: "https://i.pinimg.com/236x/d0/b4/5e/d0b45e7e97b7c50b15263c1a7eb33df8.jpg", brand: "AIDASE" },
        { title: "Titanium Glasses Frame", image: "https://i.pinimg.com/236x/95/49/78/954978b63b37afa768a63e52dde7ae58.jpg", brand: "MORDRED" },
        { title: "Black Fedora Hat Single Crease", image: "https://i.pinimg.com/236x/a2/87/3e/a2873eac5098f855848fa17ac32e051d.jpg", brand: "TOBIN" },
        { title: "Carhartt Detroit Bag", image: "https://i.pinimg.com/236x/1a/5a/34/1a5a34cc33ae2db8091c4d5058da1c83.jpg", brand: "CARHARTT" },
        { title: "Vintage Luxury Watch", image: "https://i.pinimg.com/236x/ad/31/44/ad314443dd5e94ae8d063159f7c6c1bd.jpg", brand: "OMEGA" },
        { title: "Cross Dice Necklace Silver", image: "https://i.pinimg.com/236x/d0/0b/d2/d00bd2281b97e45ab31793b4dd6c559f.jpg", brand: "GENERIC" },
        { title: "Classic Baggy Coat Zip Up", image: "https://i.pinimg.com/236x/eb/db/12/ebdb1253323572e4769a9d1cf6827ae9.jpg", brand: "GENERIC" },
        { title: "NY Yankees Gold Rope Chain", image: "https://i.pinimg.com/236x/69/5b/66/695b669f044c3c508eaad1a0ca226be8.jpg", brand: "MLB" },
        { title: "Star Keychain Bag Charm", image: "https://i.pinimg.com/236x/bc/74/49/bc7449a7ee422589c0457df14cdafc83.jpg", brand: "GENERIC" },
        { title: "Spiked Studded Punk Bracelet", image: "https://i.pinimg.com/236x/83/e0/47/83e0476c31e3a58c151d82dc801819fd.jpg", brand: "PUNK" },
        { title: "Punk Rock Skull Spike Cap", image: "https://i.pinimg.com/236x/ea/54/bf/ea54bf4496b3b8f11a9e3c2096bc22f3.jpg", brand: "ROCK" },
        { title: "Schott Fireman Clasp Jacket", image: "https://i.pinimg.com/236x/b2/d6/6c/b2d66c75decc2808e9d1b413582d0981.jpg", brand: "SCHOTT" },
        { title: "Tiger Embroidery Hoodie", image: "https://i.pinimg.com/236x/2f/8e/9f/2f8e9f81afab5e38cc6ad0bc72297208.jpg", brand: "JAPAN" },
        { title: "Sweet Knit Sweaters", image: "https://i.pinimg.com/236x/5f/ac/b9/5facb93286a1c61fd66f51127a8b004f.jpg", brand: "KNITWEAR" }
    ]
};

function getRandomPrice() {
    return Math.floor(Math.random() * (7000 - 599 + 1) + 599);
}

function createProductCard(product) {
    let priceDisplay;
    let badgeHtml = '';
    const isChristmas = document.body.classList.contains('christmas-mode');

    if (product.price) {
        // Fixed price provided (typically for Best Sellers)
        const currentPriceRaw = isChristmas ? Math.floor(product.price * 0.5) : product.price;
        const currentPrice = currentPriceRaw.toLocaleString('en-IN');

        if (product.oldPrice || isChristmas) {
            const oldPriceValue = product.oldPrice || product.price;
            const oldPrice = oldPriceValue.toLocaleString('en-IN');
            const discount = isChristmas ? 50 : Math.round(((oldPriceValue - currentPriceRaw) / oldPriceValue) * 100);
            priceDisplay = `<span class="old-price">₹${oldPrice}</span> ₹${currentPrice}`;
            badgeHtml = `<span class="badge sale">-${discount}%</span>`;
        } else {
            priceDisplay = `₹${currentPrice}`;
        }
    } else {
        // Random price for other items
        const randomP = getRandomPrice();
        const currentPriceRaw = isChristmas ? Math.floor(randomP * 0.5) : randomP;

        if (isChristmas) {
            priceDisplay = `<span class="old-price">₹${randomP.toLocaleString('en-IN')}</span> ₹${currentPriceRaw.toLocaleString('en-IN')}`;
            badgeHtml = `<span class="badge sale">-50%</span>`;
        } else {
            priceDisplay = `₹${randomP.toLocaleString('en-IN')}`;
        }
    }

    const link = `product-detail.html?title=${encodeURIComponent(product.title)}`;

    return `
        <a href="${link}" class="product-card">
            <div class="product-img-box">
                ${badgeHtml}
                <img src="${product.image}" alt="${product.title}" loading="lazy" onerror="this.src='assets/bg.jpg'">
                <div class="product-actions">
                    <button class="action-btn"><i data-lucide="shopping-bag"></i></button>
                    <button class="action-btn"><i data-lucide="heart"></i></button>
                </div>
            </div>
            <div class="product-details">
                <span class="brand">${product.brand}</span>
                <h4>${product.title}</h4>
                <div class="price">${priceDisplay}</div>
            </div>
        </a>
    `;
}

function loadProductDetails() {
    const titleEl = document.getElementById('detail-title');
    if (!titleEl) return; // Not on product detail page

    const urlParams = new URLSearchParams(window.location.search);
    const productTitle = urlParams.get('title');

    if (!productTitle) return;

    // Search all categories
    let foundProduct = null;
    let actualCategory = '';

    // First find the product object
    for (const category in products) {
        const item = products[category].find(p => p.title === productTitle);
        if (item) {
            foundProduct = item;
            break;
        }
    }

    if (foundProduct) {
        // Find its "actual" category (not Best Sellers) for correct sizes
        for (const category in products) {
            if (category === 'bestSellers') continue;
            const item = products[category].find(p => p.title === productTitle);
            if (item) {
                actualCategory = category;
                break;
            }
        }

        // Populate Data
        document.getElementById('detail-image').src = foundProduct.image;
        document.getElementById('detail-brand').textContent = foundProduct.brand;
        titleEl.textContent = foundProduct.title;
        document.getElementById('breadcrumb-current').textContent = foundProduct.title;
        document.title = `${foundProduct.title} | GARIBI`;

        // Price Logic
        let priceDisplay;
        if (foundProduct.price) {
            const currentPrice = foundProduct.price.toLocaleString('en-IN');
            if (foundProduct.oldPrice) {
                const oldPrice = foundProduct.oldPrice.toLocaleString('en-IN');
                const discount = Math.round(((foundProduct.oldPrice - foundProduct.price) / foundProduct.oldPrice) * 100);
                priceDisplay = `<span class="old-price" style="font-size: 1rem; color: #aaa;">₹${oldPrice}</span> ₹${currentPrice} <span class="badge sale" style="position:static; margin-left:10px;">-${discount}%</span>`;
            } else {
                priceDisplay = `₹${currentPrice}`;
            }
        } else {
            const price = getRandomPrice().toLocaleString('en-IN');
            priceDisplay = `₹${price}`;
        }
        document.getElementById('detail-price').innerHTML = priceDisplay;

        // Dynamic Sizes
        const sizeContainer = document.querySelector('.detail-size-selector');
        const sizeSection = document.querySelector('.size-section');

        if (sizeContainer && sizeSection) {
            if (actualCategory === 'accessories') {
                sizeSection.style.display = 'none';
                // For cart logic: auto-select "One Size"
                sizeContainer.innerHTML = '<button type="button" class="active">One Size</button>';
            } else {
                sizeSection.style.display = 'block';
                let sizes = ['XS', 'S', 'M', 'L', 'XL', 'XXL']; // Default
                if (actualCategory === 'jeans') {
                    sizes = ['28', '29', '30', '31', '32'];
                } else if (actualCategory === 'shoes') {
                    sizes = ['7', '8', '9', '10', '11'];
                }
                sizeContainer.innerHTML = sizes.map(size => `<button type="button">${size}</button>`).join('');
            }
        }

        // Interaction Logic
        setupProductInteractions(foundProduct);
    }
}

function setupProductInteractions(product) {
    const likeBtn = document.querySelector('.like-btn');
    const shareBtn = document.querySelector('.share-btn');
    const addToCartBtn = document.querySelector('.add-to-cart-btn');

    // Wishlist Toggle
    if (likeBtn) {
        likeBtn.addEventListener('click', () => {
            likeBtn.classList.toggle('liked');
            if (likeBtn.classList.contains('liked')) {
                alert(`${product.title} added to Wishlist!`);
            }
        });
    }

    // Share Functionality
    if (shareBtn) {
        shareBtn.addEventListener('click', async () => {
            if (navigator.share) {
                try {
                    await navigator.share({
                        title: product.title,
                        text: `Check out ${product.title} on GARIBI!`,
                        url: window.location.href
                    });
                } catch (err) {
                    console.log('Error sharing:', err);
                }
            } else {
                // Fallback
                navigator.clipboard.writeText(window.location.href);
                alert('Link copied to clipboard!');
            }
        });
    }

    // Add to Cart Demo
    if (addToCartBtn) {
        addToCartBtn.addEventListener('click', () => {
            // Check if size is selected
            const activeSize = document.querySelector('.detail-size-selector button.active');
            if (activeSize) {
                showNotification('Added to Bag', `${product.title} has been added.`);

                // Save to localStorage for Cart Page
                let cart = JSON.parse(localStorage.getItem('cart') || '[]');
                cart.push({
                    title: product.title,
                    price: product.price || getRandomPrice(),
                    image: product.image,
                    brand: product.brand,
                    size: activeSize.innerText
                });
                localStorage.setItem('cart', JSON.stringify(cart));
            } else {
                alert('Please select a size first.');
            }
        });
    }

    // Size Selection Logic
    const sizeBtns = document.querySelectorAll('.detail-size-selector button');
    sizeBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            sizeBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
        });
    });
}

function renderSection(containerId, items) {
    const container = document.getElementById(containerId);
    if (!container) return;

    // Clear existing placeholder content if any
    container.innerHTML = '';

    items.forEach(item => {
        container.innerHTML += createProductCard(item);
    });
}

// Render all sections on load
document.addEventListener('DOMContentLoaded', () => {
    // We strictly use setTimeout to ensure the DOM elements (if dynamically inserted later) are ready, 
    // or just to push it to the end of the stack.
    setTimeout(() => {
        renderSection('best-sellers-container', products.bestSellers);
        renderSection('tees-container', products.tees);
        renderSection('jeans-container', products.jeans);
        renderSection('jackets-container', products.jackets);
        renderSection('hoodies-container', products.hoodies);
        renderSection('shoes-container', products.shoes);
        renderSection('accessories-container', products.accessories);

        // Load Product Detail if present
        loadProductDetails();

        // Re-initialize icons for new content
        if (window.lucide) lucide.createIcons();
    }, 100);
});

// --- Global Password Toggle Helper ---
window.togglePassword = function (inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;

    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';

    // Update icon
    btn.innerHTML = `<i data-lucide="${isPassword ? 'eye-off' : 'eye'}"></i>`;
    if (window.lucide) {
        lucide.createIcons();
    }
};
