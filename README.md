# Eclipse

A small Pinterest-inspired idea collecting app built with Python, Flask, and SQLite.

## Run locally

1. Use Python 3.10 or newer.
2. Create and activate a virtual environment (optional but recommended).
3. Install dependencies: `pip install -r requirements.txt`
4. Start the app: `python app.py`
5. Open http://127.0.0.1:5000

The SQLite database (`eclipse.db`) is created automatically and stores account records (including password hashes), boards, pins, and saves. Uploaded images are saved locally in `static/uploads/` (8 MB maximum). The first run creates `.eclipse_secret_key` so browser login sessions survive page refreshes and app restarts. Keep that file private and backed up with the database; deleting it signs users out of existing browser sessions. For a host with persistent storage, set `ECLIPSE_DATA_DIR` to its persistent directory; the database, session key, and uploaded images will be stored there. Set `ECLIPSE_SECRET_KEY` to a long random value before deploying, and serve behind HTTPS. `FLASK_DEBUG=1` enables the development debugger; leave it off outside local development.

## Included

- Account registration, password hashing, login and logout
- Responsive image discovery feed with search
- Pin creation from an image URL or local image upload, with creator-only deletion
- Personal boards, save/unsave controls, and board deletion
- Editable pins and creator profiles, including profile photos and bios
- Creator following feed, pin likes, and comments
- User reporting and an admin-only moderation queue
- Password changes, CSRF protection, secure cookie settings, and security headers
- Image byte validation, image re-encoding, and upload size/pixel limits

Before a broad public launch, configure `ECLIPSE_ADMIN_EMAIL` to an account you control, set up email verification and password recovery, and establish a moderation response process and database backups. Email features require a managed email provider.

## Deploy from GitHub with Render

1. Create a GitHub repository and push this project (keep `.gitignore` so local database, uploads, and secret files stay out of GitHub).
2. In Render, create a new Blueprint and connect the GitHub repository.
3. Render reads `render.yaml`, creates an always-on web service, and mounts persistent storage at `/var/data` for the SQLite database and uploaded images. This configuration uses Render's paid Starter service plan because its free web services sleep when idle and don't support persistent disks.
4. After deployment, open the service's `onrender.com` URL. Pushes to the connected branch can trigger automatic deploys.

The Render Blueprint creates the secret key for you. Do not commit `.eclipse_secret_key`, `eclipse.db`, or user uploads to GitHub.
