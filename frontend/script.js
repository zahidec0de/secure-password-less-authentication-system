// Shared secret key for AES encryption (must match backend)
const ENCRYPTION_KEY = "4Up82wHUdKR68-fS8KWVf3AAyA99AEKO"; // Truncated FERNET_KEY to 32 bytes for AES-256

// Encrypt function using CryptoJS
function encryptData(data) {
    return CryptoJS.AES.encrypt(data, ENCRYPTION_KEY).toString();
}

// Decrypt function (not used on frontend, but included for reference)
function decryptData(encryptedData) {
    const bytes = CryptoJS.AES.decrypt(encryptedData, ENCRYPTION_KEY);
    return bytes.toString(CryptoJS.enc.Utf8);
}

async function registerUser() {
    const email = document.getElementById('register-email').value;
    const phone = document.getElementById('register-phone').value;
    const cpr = document.getElementById('register-cpr').value;
    const answer1 = document.getElementById('register-answer1').value;
    const answer2 = document.getElementById('register-answer2').value;
    const feedback = document.getElementById('register-feedback');

    if (!email || !phone || !cpr || !answer1 || !answer2) {
        showFeedback(feedback, 'Please fill in all fields', 'danger');
        return;
    }

    // Encrypt sensitive fields before sending
    const encryptedCpr = encryptData(cpr);
    const encryptedEmail = encryptData(email);
    const encryptedPhone = encryptData(phone);

    showFeedback(feedback, 'Registering...', 'info');

    try {
        const response = await fetch('http://127.0.0.1:8000/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                email: encryptedEmail, 
                phone: encryptedPhone, 
                cpr: encryptedCpr, 
                answer1, 
                answer2 
            })
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.detail || 'Registration failed');
        }

        showFeedback(feedback, 'Registration successful! Check the server console for the email verification link.', 'success');
    } catch (err) {
        showFeedback(feedback, err.message, 'danger');
    }
}

let currentCpr = null;

async function startLogin() {
    const cpr = document.getElementById('login-cpr').value;
    const method = document.getElementById('login-method').value;
    const feedback = document.getElementById('login-feedback');
    const otpSection = document.getElementById('otp-input-section');
    const securityQuestionsSection = document.getElementById('security-questions-section');

    if (!cpr) {
        showFeedback(feedback, 'Please enter your CPR Number', 'danger');
        return;
    }

    // Encrypt CPR before sending
    const encryptedCpr = encryptData(cpr);

    showFeedback(feedback, 'Initiating login...', 'info');
    currentCpr = encryptedCpr;

    try {
        const response = await fetch('http://127.0.0.1:8000/login/initiate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cpr: encryptedCpr, method })
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.detail || 'Failed to initiate login');
        }

        if (method === 'magic_link') {
            showFeedback(feedback, 'Magic link generated. Click the link below. (Dev: Link is shown for testing)', 'info');
            const debugLink = document.createElement('div');
            debugLink.id = 'debug-link';
            debugLink.className = 'alert alert-warning mt-2';
            debugLink.innerHTML = 'Dev Magic Link: Check console for now (to be replaced with email)';
            document.getElementById('login-form').appendChild(debugLink);
            otpSection.classList.add('d-none');
            securityQuestionsSection.classList.add('d-none');
        } else if (method === 'otp_sms') {
            showFeedback(feedback, 'OTP generated. Enter the OTP below. (Dev: OTP is shown below for testing)', 'info');
            const debugOtp = document.createElement('div');
            debugOtp.id = 'debug-otp';
            debugOtp.className = 'alert alert-warning mt-2';
            debugOtp.textContent = 'Dev OTP: Check console for now (to be replaced with SMS)';
            otpSection.insertBefore(debugOtp, otpSection.firstChild);
            otpSection.classList.remove('d-none');
            securityQuestionsSection.classList.add('d-none');
            const resendButton = document.createElement('button');
            resendButton.textContent = 'Resend OTP';
            resendButton.className = 'btn btn-link mt-2';
            resendButton.onclick = () => startLogin();
            otpSection.appendChild(resendButton);
        } else if (method === 'security_questions') {
            showFeedback(feedback, 'Answer your security questions below.', 'info');
            otpSection.classList.add('d-none');
            securityQuestionsSection.classList.remove('d-none');
        }
    } catch (err) {
        showFeedback(feedback, err.message, 'danger');
    }
}

async function submitOtp() {
    const otp = document.getElementById('otp-input').value;
    const feedback = document.getElementById('login-feedback');

    if (!otp) {
        showFeedback(feedback, 'Please enter the OTP', 'danger');
        return;
    }

    await verifyLogin(currentCpr, 'otp_sms', { otp }, feedback);
}

async function submitSecurityAnswers() {
    const answer1 = document.getElementById('answer1-input').value;
    const answer2 = document.getElementById('answer2-input').value;
    const feedback = document.getElementById('login-feedback');

    if (!answer1 || !answer2) {
        showFeedback(feedback, 'Please answer both questions', 'danger');
        return;
    }

    await verifyLogin(currentCpr, 'security_questions', { answer1, answer2 }, feedback);
}

async function verifyLogin(cpr, method, data, feedback) {
    showFeedback(feedback, 'Verifying...', 'info');
    try {
        const response = await fetch('http://127.0.0.1:8000/login/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cpr, method, data })
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.detail || 'Verification failed');
        }

        showFeedback(feedback, 'Login successful! Redirecting...', 'success');
        setTimeout(() => window.location.href = 'dashboard.html', 1000);
    } catch (err) {
        showFeedback(feedback, err.message, 'danger');
    }
}

window.addEventListener('load', async () => {
    const urlParams = new URLSearchParams(window.location.search);
    const error = urlParams.get('error');
    if (error) {
        const feedback = document.getElementById('login-feedback');
        showFeedback(feedback, decodeURIComponent(error), 'danger');
    }
});

function showFeedback(feedbackElement, message, type) {
    feedbackElement.textContent = message;
    feedbackElement.className = `alert alert-${type}`;
    feedbackElement.classList.remove('d-none');
}