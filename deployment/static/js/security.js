/**
 * Frontend validation and security for Stock Tracker Application
 */

// CSRF token handling
let csrfToken = '';

// Initialize security features when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Get CSRF token from meta tag
    const metaToken = document.querySelector('meta[name="csrf-token"]');
    if (metaToken) {
        csrfToken = metaToken.getAttribute('content');
    }

    // Apply input validation to all forms
    applyFormValidation();
    
    // Set up security event listeners
    setupSecurityListeners();
    
    // Initialize content security features
    initializeContentSecurity();
    
    // Start inactivity timer for auto-logout
    startInactivityTimer();
});

/**
 * Apply validation to all forms in the document
 */
function applyFormValidation() {
    // Get all forms
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        // Add validation on submit
        form.addEventListener('submit', function(event) {
            // Prevent form submission if validation fails
            if (!validateForm(this)) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            // Add CSRF token to form if it doesn't have one
            if (!this.querySelector('input[name="csrf_token"]') && csrfToken) {
                const csrfInput = document.createElement('input');
                csrfInput.type = 'hidden';
                csrfInput.name = 'csrf_token';
                csrfInput.value = csrfToken;
                this.appendChild(csrfInput);
            }
        });
        
        // Add real-time validation for inputs
        const inputs = form.querySelectorAll('input, select, textarea');
        inputs.forEach(input => {
            input.addEventListener('input', function() {
                validateInput(this);
            });
            
            input.addEventListener('blur', function() {
                validateInput(this);
            });
        });
    });
}

/**
 * Validate an entire form
 * @param {HTMLFormElement} form - The form to validate
 * @returns {boolean} - Whether the form is valid
 */
function validateForm(form) {
    let isValid = true;
    
    // Validate all inputs in the form
    const inputs = form.querySelectorAll('input, select, textarea');
    inputs.forEach(input => {
        if (!validateInput(input)) {
            isValid = false;
        }
    });
    
    // Check for password confirmation if present
    const password = form.querySelector('input[type="password"][id="password"]');
    const confirmPassword = form.querySelector('input[type="password"][id="confirm_password"]');
    if (password && confirmPassword) {
        if (password.value !== confirmPassword.value) {
            setInvalid(confirmPassword, 'Passwords do not match');
            isValid = false;
        }
    }
    
    return isValid;
}

/**
 * Validate a single input field
 * @param {HTMLInputElement} input - The input to validate
 * @returns {boolean} - Whether the input is valid
 */
function validateInput(input) {
    // Skip disabled or hidden inputs
    if (input.disabled || input.type === 'hidden') {
        return true;
    }
    
    // Get validation rules from attributes
    const isRequired = input.hasAttribute('required');
    const minLength = input.getAttribute('minlength');
    const maxLength = input.getAttribute('maxlength');
    const pattern = input.getAttribute('pattern');
    const inputType = input.type;
    
    // Get input value and trim whitespace
    const value = input.value.trim();
    
    // Check if required field is empty
    if (isRequired && value === '') {
        setInvalid(input, 'This field is required');
        return false;
    }
    
    // Check min length
    if (minLength && value.length < parseInt(minLength)) {
        setInvalid(input, `Must be at least ${minLength} characters`);
        return false;
    }
    
    // Check max length
    if (maxLength && value.length > parseInt(maxLength)) {
        setInvalid(input, `Must be no more than ${maxLength} characters`);
        return false;
    }
    
    // Check pattern
    if (pattern && value !== '') {
        const regex = new RegExp(pattern);
        if (!regex.test(value)) {
            setInvalid(input, 'Please enter a valid format');
            return false;
        }
    }
    
    // Type-specific validation
    if (value !== '') {
        switch (inputType) {
            case 'email':
                if (!validateEmail(value)) {
                    setInvalid(input, 'Please enter a valid email address');
                    return false;
                }
                break;
                
            case 'password':
                if (input.id === 'password' && !validatePassword(value)) {
                    setInvalid(input, 'Password must be at least 8 characters with uppercase, lowercase, number, and special character');
                    return false;
                }
                break;
                
            case 'number':
                if (isNaN(value)) {
                    setInvalid(input, 'Please enter a valid number');
                    return false;
                }
                
                // Check min/max values
                const min = input.getAttribute('min');
                const max = input.getAttribute('max');
                
                if (min && parseFloat(value) < parseFloat(min)) {
                    setInvalid(input, `Value must be at least ${min}`);
                    return false;
                }
                
                if (max && parseFloat(value) > parseFloat(max)) {
                    setInvalid(input, `Value must be no more than ${max}`);
                    return false;
                }
                break;
                
            case 'url':
                if (!validateUrl(value)) {
                    setInvalid(input, 'Please enter a valid URL');
                    return false;
                }
                break;
        }
    }
    
    // Custom validation for stock symbols
    if (input.id === 'stockSearch' || input.id === 'symbol') {
        if (value !== '' && !validateStockSymbol(value)) {
            setInvalid(input, 'Please enter a valid stock symbol');
            return false;
        }
    }
    
    // If we got here, input is valid
    setValid(input);
    return true;
}

/**
 * Mark an input as invalid with feedback
 * @param {HTMLInputElement} input - The input to mark as invalid
 * @param {string} message - The error message to display
 */
function setInvalid(input, message) {
    input.classList.add('is-invalid');
    input.classList.remove('is-valid');
    
    // Find or create feedback element
    let feedback = input.nextElementSibling;
    if (!feedback || !feedback.classList.contains('invalid-feedback')) {
        feedback = document.createElement('div');
        feedback.className = 'invalid-feedback';
        input.parentNode.insertBefore(feedback, input.nextSibling);
    }
    
    feedback.textContent = message;
}

/**
 * Mark an input as valid
 * @param {HTMLInputElement} input - The input to mark as valid
 */
function setValid(input) {
    input.classList.remove('is-invalid');
    input.classList.add('is-valid');
}

/**
 * Validate email format
 * @param {string} email - The email to validate
 * @returns {boolean} - Whether the email is valid
 */
function validateEmail(email) {
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return regex.test(email);
}

/**
 * Validate password strength
 * @param {string} password - The password to validate
 * @returns {boolean} - Whether the password meets requirements
 */
function validatePassword(password) {
    // At least 8 characters
    if (password.length < 8) {
        return false;
    }
    
    // Check for uppercase, lowercase, number, and special character
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*()_\-+={}[\]|:;"'<>,.?/~`]/.test(password);
    
    return hasUppercase && hasLowercase && hasNumber && hasSpecial;
}

/**
 * Validate URL format
 * @param {string} url - The URL to validate
 * @returns {boolean} - Whether the URL is valid
 */
function validateUrl(url) {
    try {
        new URL(url);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Validate stock symbol format
 * @param {string} symbol - The stock symbol to validate
 * @returns {boolean} - Whether the symbol is valid
 */
function validateStockSymbol(symbol) {
    // Stock symbols are typically 1-5 uppercase letters
    // Some may include dots or hyphens (e.g., BRK.A, BF-B)
    const regex = /^[A-Z]{1,5}(\.[A-Z]|-[A-Z])?$/;
    return regex.test(symbol);
}

/**
 * Set up security-related event listeners
 */
function setupSecurityListeners() {
    // Sanitize all inputs on blur to prevent XSS
    document.addEventListener('blur', function(event) {
        if (event.target.tagName === 'INPUT' || event.target.tagName === 'TEXTAREA') {
            event.target.value = sanitizeInput(event.target.value);
        }
    }, true);
    
    // Add CSRF token to all AJAX requests
    const originalFetch = window.fetch;
    window.fetch = function(url, options = {}) {
        // Only add CSRF token to same-origin requests
        if (new URL(url, window.location.origin).origin === window.location.origin) {
            options.headers = options.headers || {};
            options.headers['X-CSRF-Token'] = csrfToken;
        }
        return originalFetch.call(this, url, options);
    };
    
    // Add CSRF token to all XHR requests
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function() {
        this.addEventListener('readystatechange', function() {
            if (this.readyState === 1) {
                this.setRequestHeader('X-CSRF-Token', csrfToken);
            }
        });
        originalOpen.apply(this, arguments);
    };
}

/**
 * Sanitize user input to prevent XSS
 * @param {string} input - The input to sanitize
 * @returns {string} - The sanitized input
 */
function sanitizeInput(input) {
    if (typeof input !== 'string') {
        return input;
    }
    
    // Replace potentially dangerous characters
    return input
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Initialize content security features
 */
function initializeContentSecurity() {
    // Prevent clickjacking
    if (window.self !== window.top) {
        // If page is in an iframe, blank it out
        document.body.innerHTML = '';
        window.top.location = window.self.location;
    }
    
    // Prevent data leakage
    document.addEventListener('copy', function(e) {
        // Prevent copying of sensitive data
        const selection = window.getSelection().toString();
        if (selection.includes('password') || selection.includes('token')) {
            e.preventDefault();
        }
    });
}

/**
 * Start inactivity timer for auto-logout
 */
function startInactivityTimer() {
    let inactivityTimeout;
    const logoutTime = 15 * 60 * 1000; // 15 minutes
    
    function resetTimer() {
        clearTimeout(inactivityTimeout);
        inactivityTimeout = setTimeout(logout, logoutTime);
    }
    
    function logout() {
        // Redirect to logout page
        window.location.href = '/auth/logout';
    }
    
    // Reset timer on user activity
    ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach(event => {
        document.addEventListener(event, resetTimer, false);
    });
    
    // Start the timer
    resetTimer();
}

/**
 * Add CSRF token to AJAX request
 * @param {object} data - The data object to add the token to
 * @returns {object} - The data object with the token added
 */
function addCsrfToken(data) {
    data = data || {};
    data.csrf_token = csrfToken;
    return data;
}

/**
 * Make a secure AJAX request
 * @param {string} url - The URL to request
 * @param {string} method - The HTTP method to use
 * @param {object} data - The data to send
 * @param {function} successCallback - The callback for successful requests
 * @param {function} errorCallback - The callback for failed requests
 */
function secureAjax(url, method, data, successCallback, errorCallback) {
    // Add CSRF token to data
    data = addCsrfToken(data);
    
    // Create request options
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        }
    };
    
    // Add body for non-GET requests
    if (method !== 'GET') {
        options.body = JSON.stringify(data);
    }
    
    // Make the request
    fetch(url, options)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (successCallback) {
                successCallback(data);
            }
        })
        .catch(error => {
            console.error('Request failed:', error);
            if (errorCallback) {
                errorCallback(error);
            }
        });
}

/**
 * Update password strength meter
 * @param {string} password - The password to evaluate
 * @param {HTMLElement} strengthBar - The progress bar element
 * @param {HTMLElement} strengthText - The text element
 */
function updatePasswordStrength(password, strengthBar, strengthText) {
    let strength = 0;
    let feedback = '';

    // Length check
    if (password.length >= 8) {
        strength += 25;
    }

    // Uppercase check
    if (/[A-Z]/.test(password)) {
        strength += 25;
    }

    // Lowercase check
    if (/[a-z]/.test(password)) {
        strength += 25;
    }

    // Number check
    if (/[0-9]/.test(password)) {
        strength += 12.5;
    }

    // Special character check
    if (/[^A-Za-z0-9]/.test(password)) {
        strength += 12.5;
    }

    // Update progress bar
    strengthBar.style.width = strength + '%';
    
    // Update color based on strength
    if (strength < 25) {
        strengthBar.className = 'progress-bar bg-danger';
        feedback = 'Too weak';
    } else if (strength < 50) {
        strengthBar.className = 'progress-bar bg-warning';
        feedback = 'Weak';
    } else if (strength < 75) {
        strengthBar.className = 'progress-bar bg-info';
        feedback = 'Medium';
    } else {
        strengthBar.className = 'progress-bar bg-success';
        feedback = 'Strong';
    }

    strengthText.textContent = 'Password strength: ' + feedback;
}

// Export functions for use in other scripts
window.StockTrackerSecurity = {
    validateForm,
    validateInput,
    sanitizeInput,
    addCsrfToken,
    secureAjax,
    updatePasswordStrength
};
