/**
 * Sample vulnerable JavaScript code - XSS and other issues
 * Used for testing MANTISHACK scan, agentic, and analyze modes
 */

// VULNERABLE: DOM-based XSS
function displayUserInput() {
    const userInput = document.getElementById('user_input').value;
    // Direct innerHTML assignment - XSS vulnerability
    document.getElementById('output').innerHTML = userInput;
}

// VULNERABLE: Reflected XSS via query parameter
function handleSearchQuery() {
    const query = new URLSearchParams(window.location.search).get('q');
    // Unsanitized query in HTML - reflected XSS
    document.write('<p>Search results for: ' + query + '</p>');
}

// VULNERABLE: Eval usage
function executeUserCode(code) {
    // eval() is extremely dangerous - arbitrary code execution
    eval(code);
}

// VULNERABLE: Hardcoded API key
const API_KEY = "sk-1234567890abcdef";
const SECRET_TOKEN = "super_secret_token_12345";

function fetchUserData() {
    // Using hardcoded credentials in client-side code
    fetch('https://api.example.com/users', {
        headers: {
            'Authorization': 'Bearer ' + SECRET_TOKEN,
            'X-API-Key': API_KEY
        }
    });
}

// VULNERABLE: Insecure localStorage usage
function storeUserCredentials(username, password) {
    // Storing sensitive data in localStorage - insecure
    localStorage.setItem('username', username);
    localStorage.setItem('password', password);
}

// VULNERABLE: Missing CSRF token
function updateProfile(userData) {
    fetch('/api/profile', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        // No CSRF token - vulnerable to CSRF attacks
        body: JSON.stringify(userData)
    });
}

// VULNERABLE: Insecure random number generation
function generateSessionToken() {
    // Math.random() is not cryptographically secure
    return Math.random().toString(36).substring(7);
}

// VULNERABLE: Prototype pollution
function mergeObjects(target, source) {
    for (const key in source) {
        // No validation - allows prototype pollution
        target[key] = source[key];
    }
    return target;
}

// VULNERABLE: Regular expression DoS
function validateEmail(email) {
    // Inefficient regex - ReDoS vulnerability
    const pattern = /^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.([a-zA-Z0-9]+)*$/;
    return pattern.test(email);
}

export { displayUserInput, handleSearchQuery, fetchUserData };
