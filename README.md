# SHAIL Website

This website runs as a Node.js web service. Static-only hosting will not provide the protected admin routes or shared business data.

## Local run

1. Install Node.js 22.13 or newer.
2. Open PowerShell in this folder and run `./start-server.ps1`.
3. Enter the admin password when prompted. The prompt does not echo the password.
4. Open the local URL printed by the server. The admin username defaults to `Nitya`.

The server stores admin data and login sessions in `data/shail.sqlite`. That folder is ignored by Git and must be backed up.

## Checks

Run `npm test` to verify admin access control, shared data, persistent sessions, and logout.

## Hosting

Deploy this repository as a Node web service, not as a static site. Use `npm install` as the build command and `npm start` as the start command. Configure these environment variables in the hosting provider's private settings:

- `ADMIN_PASSWORD`: a unique secret with at least 14 characters.
- `ADMIN_USERNAME`: optional; defaults to `Nitya`.
- `HOST`: set to `0.0.0.0` for providers that require public interface binding.
- `ADMIN_COOKIE_SECURE`: set to `1` when served over HTTPS.
- `TRUST_PROXY`: set to `1` only when the host is a trusted reverse proxy that sets `X-Forwarded-For`.
- `DATA_DIR`: set to the mounted persistent-disk directory, for example `/var/data`.
- `PORT`: use the port provided by the host.

Use one server instance for SQLite. Attach persistent disk storage at `DATA_DIR`; otherwise the database can be lost when the host replaces the instance. Back up the database file regularly.

The Render Blueprint in `render.yaml` configures a single Node web service and persistent disk. Render will still require an account, a private `ADMIN_PASSWORD` value, and a paid service/disk plan for persistent storage.

The password previously shared in chat should be considered exposed. Set a different strong password in the host's private environment settings.
