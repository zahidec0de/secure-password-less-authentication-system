# secure-password-less-authentication-system
1. Go to the directory where you cloned the project:
2. Install requirements: pip install -r requirements.txt
3. From the terminal, go to the backend directory and run: python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
4. From the terminal, go to the frontend directory and run: python -m http.server 8001
5. Open the browser and go to: http://127.0.0.1:8001
6. Once you register:
  - Go back to the backend console.
  - Copy the JWT verification link.
  - Open it in your browser to verify your email.
    
To log in:
  - Enter your CPR and select a 2FA method (CPR is set to 6 digits for testing)
  - Go back to the backend console.
  - For OTP: Copy the 6-digit code, enter it (3 attempts).
  - For Magic Link: Copy the link, open it to log in.
  - For Security Questions: Answer the questions you set.

To log out:
- Click "Logout" on the page.
