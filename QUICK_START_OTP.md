# Quick Start: Get OTP Emails Working

## Why You're Not Receiving OTP Emails

Your code was showing the 2FA code in a browser alert instead of sending it via email. I've now updated it to use Novu email notifications.

---

## Steps to Fix (Choose ONE option):

### ⚡ OPTION 1: Quick Test (Use Novu Cloud - Recommended)

1. **Sign up for Novu** (Free):
   - Go to: https://web.novu.co/
   - Sign up with your email
   - Create a new application

2. **Get Your API Credentials**:
   - Go to Settings → API Keys
   - Copy your **API Key**
   - Copy your **Application Identifier**

3. **Create `.env` file** in your project root:
   ```env
   NOVU_API_KEY=your_api_key_here
   NOVU_APP_ID=your_app_identifier_here
   PORT=3000
   ```

4. **Install Dependencies**:
   ```bash
   cd "c:\Users\Anil\OneDrive\Desktop\MY PROJECTS\GARIBI"
   npm install
   ```

5. **Create Email Workflow in Novu Dashboard**:
   - Go to Workflows → Create Workflow
   - Name: `2fa-code`
   - Add Email Step
   - Subject: `Your GARIBI Verification Code`
   - Content:
   ```html
   <h2>Hello {{userName}},</h2>
   <p>Your two-factor authentication code is:</p>
   <div style="background: #000; color: #fff; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px;">
       {{code}}
   </div>
   <p>This code will expire in 10 minutes.</p>
   ```
   - Click **Update** and **Activate**

6. **Start the Notification Server**:
   ```bash
   npm start
   ```

7. **Test Login**:
   - Open `login.html` in your browser
   - Login with any user from `credentials.md`
   - Check your email for the OTP!

---

### 🔧 OPTION 2: Use Existing Novu Setup

If you already have Novu configured in the `novu-next` folder:

1. **Check if Novu is running**:
   ```bash
   cd novu-next
   # Check if there's a docker-compose file
   docker-compose up -d
   ```

2. **Update `.env` to point to local Novu**:
   ```env
   NOVU_API_KEY=your_local_api_key
   NOVU_APP_ID=your_local_app_id
   PORT=3000
   ```

3. **Start notification server**:
   ```bash
   cd ..
   npm start
   ```

---

### 🚀 OPTION 3: Quick Fallback (No Email, Just Console)

If you want to test without setting up Novu right now:

The code already has a fallback! If the notification server is not running, it will show the code in an alert with a message saying "Notification server offline".

**To test this**:
1. Just login normally
2. The code will appear in an alert (like before)
3. But you'll see a message that the server is offline

---

## Troubleshooting

### Issue: "Failed to fetch" error
**Solution**: Make sure the notification server is running on port 3000
```bash
npm start
```

### Issue: Email not received
**Checklist**:
- ✅ Notification server is running (`npm start`)
- ✅ `.env` file has correct NOVU_API_KEY
- ✅ Workflow `2fa-code` exists in Novu dashboard
- ✅ Workflow is **activated** (not draft)
- ✅ Check spam/junk folder
- ✅ Email address is correct in user database

### Issue: "CORS error"
**Solution**: The notification server already has CORS enabled. Make sure you're accessing the site via the same domain/port.

---

## Testing the Full Flow

1. **Start notification server**:
   ```bash
   npm start
   ```
   You should see:
   ```
   ╔═══════════════════════════════════════════════════════╗
   ║   🚀 GARIBI Novu Notification Server                 ║
   ║   Status: Running                                     ║
   ║   Port: 3000                                          ║
   ╚═══════════════════════════════════════════════════════╝
   ```

2. **Open login page** in browser

3. **Login with test account**:
   - Email: `admin@garibi.com`
   - Password: `admin`

4. **Check your email** for the 6-digit code

5. **Enter the code** in the verification form

6. **Success!** You should be logged in

---

## What I Changed

### Before (Old Code):
```javascript
alert(`Your 2FA Verification Code is: ${code}`);
```

### After (New Code):
```javascript
// Send via Novu email
fetch('http://localhost:3000/api/notify/2fa-code', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        email: email,
        name: user.name,
        code: code
    })
})
.then(response => response.json())
.then(data => {
    if (data.success) {
        alert(`A 6-digit verification code has been sent to ${email}. Please check your email.`);
    } else {
        // Fallback if email fails
        alert(`Your 2FA Verification Code is: ${code}\n\n(Email delivery failed)`);
    }
})
```

---

## Next Steps

Once you have OTP emails working, you can also enable:
- ✅ Login success notifications
- ✅ Failed login alerts (after 3 wrong passwords)
- ✅ Password reset emails
- ✅ Account locked alerts

All the code is ready - just need to create the workflows in Novu dashboard!

---

**Need Help?**
Check the detailed guide: `documentation/NOVU_INTEGRATION.md`
