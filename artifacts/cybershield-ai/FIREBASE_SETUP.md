# Firebase setup

The app can analyze links and messages without Firebase. Until Firebase is configured, scan history is stored only in this browser and account features are unavailable.

## 1. Create a Firebase project

In the Firebase console:

1. Create a project and register a Web App.
2. Under **Authentication → Sign-in method**, enable **Email/Password**.
3. Create a Cloud Firestore database.
4. Add the development and published app domains to **Authentication → Settings → Authorized domains**.

## 2. Add the web configuration

Copy `artifacts/cybershield-ai/.env.example` to `artifacts/cybershield-ai/.env.local` and fill in the Firebase web-app values:

- `VITE_FIREBASE_API_KEY`
- `VITE_FIREBASE_AUTH_DOMAIN`
- `VITE_FIREBASE_PROJECT_ID`
- `VITE_FIREBASE_APP_ID`
- `VITE_FIREBASE_MESSAGING_SENDER_ID`

These values identify a Firebase web app and are intended for browser configuration. Never place a Firebase Admin private key or service-account credential in frontend code or these variables.

## 3. Apply Firestore security rules

Publish `artifacts/cybershield-ai/firestore.rules` in the Firebase console under **Firestore Database → Rules**, or deploy it with the Firebase CLI. The rules restrict user, scan-history, and learning-progress records to the authenticated owner.

Scan documents intentionally contain only scan metadata. The app must not save the submitted message, a full URL, or URL query/path data to Firestore. A URL scan may save only its hostname.

## 4. Restart the web app

Restart the app after changing `.env.local`. Check the account/settings screens for Firebase readiness. Until the configuration is complete, the app remains in local-only mode and does not claim that cloud sync or email/password authentication is available.
