# Cyber Shield

A responsive URL risk scanner with a Node.js API, heuristic risk scoring, and a PhishIndex domain blocklist.

## Architecture

- `public/`: Firebase Hosting frontend.
- `backend/`: Express API deployed separately on Render.
- The browser sends URLs to `POST /api/scan`; the API returns a transparent risk score and threat-intelligence result.
- Scan history is stored only in the visitor's browser local storage.

## Local development

1. Install Node.js 20 or newer.
2. In `backend/`, run `npm install`, then `npm test`, then `npm start`.
3. Serve `public/` with Firebase CLI or another static server.
4. Set the API endpoint in `public/script.js` if using a different backend host.

## Deployment

- Render uses `render.yaml` and deploys the `backend` directory.
- Firebase Hosting serves the `public` directory: run `firebase deploy --only hosting` from the repository root after logging in and selecting the Firebase project.

## Important limitations

This is a defensive educational scanner, not a guarantee that a URL is safe. Heuristic scores are indicators, not proof of maliciousness. A domain absent from the feed may still be malicious. The API does not visit or fetch submitted URLs.
