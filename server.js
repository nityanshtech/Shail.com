"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "127.0.0.1";
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, "data"));
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "Nitya";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SESSION_COOKIE = "shail_admin_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILED_LOGINS = 8;
const MAX_DATA_BODY_BYTES = 16 * 1024 * 1024;
const ADMIN_DATA_KEYS = new Set([
    "shail_admin_products",
    "shail_aquarium_items",
    "shail_billing_records",
    "shail_gallery_items",
    "shail_shop_timings",
    "shail_business_settings"
]);

fs.mkdirSync(DATA_DIR, { recursive: true });
const database = new DatabaseSync(path.join(DATA_DIR, "shail.sqlite"));
database.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS app_data (
        data_key TEXT PRIMARY KEY,
        data_value TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS admin_sessions (
        token_hash TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS login_attempts (
        client_key TEXT PRIMARY KEY,
        failures INTEGER NOT NULL,
        window_ends INTEGER NOT NULL,
        locked_until INTEGER NOT NULL
    );
`);

if (ADMIN_PASSWORD.length < 14) {
    console.error("Set ADMIN_PASSWORD to a strong password of at least 14 characters.");
    process.exit(1);
}

const digest = value => crypto.createHash("sha256").update(value).digest();
const passwordsMatch = supplied => crypto.timingSafeEqual(digest(supplied), digest(ADMIN_PASSWORD));
const usernamesMatch = supplied => crypto.timingSafeEqual(digest(supplied), digest(ADMIN_USERNAME));

function sendJson(response, status, value, headers = {}) {
    response.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        ...headers
    });
    response.end(JSON.stringify(value));
}

function readJson(request, limit = 4096) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        let rejected = false;

        request.on("data", chunk => {
            size += chunk.length;
            if (size > limit) {
                rejected = true;
                reject(Object.assign(new Error("Request is too large."), { statusCode: 413 }));
                request.destroy();
                return;
            }
            chunks.push(chunk);
        });
        request.on("end", () => {
            if (rejected) return;
            try {
                resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
            } catch {
                reject(Object.assign(new Error("Invalid request."), { statusCode: 400 }));
            }
        });
        request.on("error", reject);
    });
}

function clientAddress(request) {
    if (process.env.TRUST_PROXY === "1") {
        const forwardedFor = request.headers["x-forwarded-for"];
        if (typeof forwardedFor === "string" && forwardedFor.trim()) {
            return forwardedFor.split(",")[0].trim();
        }
    }
    return request.socket.remoteAddress || "unknown";
}

function getSession(request) {
    const cookieHeader = request.headers.cookie || "";
    const token = cookieHeader
        .split(";")
        .map(value => value.trim())
        .find(value => value.startsWith(`${SESSION_COOKIE}=`))
        ?.slice(SESSION_COOKIE.length + 1);

    if (!token) return null;
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const session = database.prepare(
        "SELECT username, expires_at FROM admin_sessions WHERE token_hash = ?"
    ).get(tokenHash);
    if (!session) return null;
    if (session.expires_at <= Date.now()) {
        database.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").run(tokenHash);
        return null;
    }
    return { tokenHash, username: session.username, expiresAt: session.expires_at };
}

function cookieOptions() {
    return `Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}` +
        (process.env.ADMIN_COOKIE_SECURE === "1" ? "; Secure" : "");
}

function handleLogin(request, response) {
    const address = clientAddress(request);
    const attempts = database.prepare(
        "SELECT failures, window_ends, locked_until FROM login_attempts WHERE client_key = ?"
    ).get(address);
    if (attempts?.locked_until > Date.now()) {
        sendJson(response, 429, { message: "Too many attempts. Try again in 15 minutes." });
        return;
    }

    readJson(request).then(credentials => {
        const username = typeof credentials.username === "string" ? credentials.username : "";
        const password = typeof credentials.password === "string" ? credentials.password : "";
        const valid = usernamesMatch(username) && passwordsMatch(password);

        if (!valid) {
            const now = Date.now();
            const current = database.prepare(
                "SELECT failures, window_ends FROM login_attempts WHERE client_key = ?"
            ).get(address);
            const failures = current && current.window_ends > now ? current.failures + 1 : 1;
            const windowEnds = current && current.window_ends > now ? current.window_ends : now + LOGIN_WINDOW_MS;
            const lockedUntil = failures >= MAX_FAILED_LOGINS ? now + LOGIN_WINDOW_MS : 0;
            database.prepare(`
                INSERT INTO login_attempts (client_key, failures, window_ends, locked_until)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(client_key) DO UPDATE SET
                    failures = excluded.failures,
                    window_ends = excluded.window_ends,
                    locked_until = excluded.locked_until
            `).run(address, failures, windowEnds, lockedUntil);
            sendJson(response, lockedUntil ? 429 : 401, {
                message: lockedUntil ? "Too many attempts. Try again in 15 minutes." : "Invalid username or password."
            });
            return;
        }

        database.prepare("DELETE FROM login_attempts WHERE client_key = ?").run(address);
        const token = crypto.randomBytes(32).toString("base64url");
        const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
        database.prepare(`
            INSERT INTO admin_sessions (token_hash, username, expires_at)
            VALUES (?, ?, ?)
        `).run(tokenHash, ADMIN_USERNAME, Date.now() + SESSION_TTL_MS);
        sendJson(response, 200, { ok: true }, {
            "Set-Cookie": `${SESSION_COOKIE}=${token}; ${cookieOptions()}`
        });
    }).catch(error => {
        sendJson(response, error.statusCode || 400, { message: "Invalid login request." });
    });
}

function serveFile(request, response, pathname) {
    const relativePath = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
    const filePath = path.resolve(ROOT, relativePath);
    const relativeToRoot = path.relative(ROOT, filePath);
    if (relativeToRoot.startsWith("..") || path.isAbsolute(relativeToRoot)) {
        response.writeHead(404).end("Not found");
        return;
    }

    const dataRelativePath = path.relative(ROOT, DATA_DIR);
    const inDataDirectory = dataRelativePath &&
        (relativeToRoot === dataRelativePath || relativeToRoot.startsWith(`${dataRelativePath}${path.sep}`));
    const blocked = inDataDirectory || relativeToRoot.split(path.sep).some(part =>
        part.startsWith(".") || part === "node_modules" || part === "server.js" || part.endsWith(".ps1") || part.endsWith(".docx")
    );
    if (blocked) {
        response.writeHead(404).end("Not found");
        return;
    }

    fs.stat(filePath, (statError, stats) => {
        if (statError || !stats.isFile()) {
            response.writeHead(404).end("Not found");
            return;
        }

        const contentTypes = {
            ".css": "text/css; charset=utf-8",
            ".html": "text/html; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".svg": "image/svg+xml",
            ".webp": "image/webp"
        };
        response.writeHead(200, {
            "Content-Type": contentTypes[path.extname(filePath).toLowerCase()] || "application/octet-stream",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Cache-Control": relativeToRoot === "admin-dashboard.html" ? "no-store" : "no-cache"
        });

        if (request.method === "HEAD") {
            response.end();
            return;
        }
        fs.createReadStream(filePath).pipe(response);
    });
}

const server = http.createServer((request, response) => {
    let url;
    let requestPath;
    try {
        url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
        requestPath = decodeURIComponent(url.pathname);
    } catch {
        response.writeHead(400).end("Bad request");
        return;
    }

    if (requestPath === "/api/admin/login" && request.method === "POST") {
        handleLogin(request, response);
        return;
    }

    if (requestPath === "/api/health" && request.method === "GET") {
        sendJson(response, 200, { ok: true });
        return;
    }

    if (requestPath === "/api/admin/logout" && request.method === "POST") {
        const session = getSession(request);
        if (session) {
            database.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").run(session.tokenHash);
        }
        sendJson(response, 200, { ok: true }, {
            "Set-Cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0` +
                (process.env.ADMIN_COOKIE_SECURE === "1" ? "; Secure" : "")
        });
        return;
    }

    if (requestPath === "/api/admin/session" && request.method === "GET") {
        const session = getSession(request);
        sendJson(response, session ? 200 : 401, session ? { ok: true, username: session.username } : { ok: false });
        return;
    }

    if (requestPath === "/api/site-data" && request.method === "GET") {
        const publicKeys = [
            "shail_admin_products",
            "shail_aquarium_items",
            "shail_gallery_items",
            "shail_shop_timings",
            "shail_business_settings"
        ];
        const publicData = {};
        const selectValue = database.prepare("SELECT data_value FROM app_data WHERE data_key = ?");
        publicKeys.forEach(key => {
            const row = selectValue.get(key);
            if (row) publicData[key] = JSON.parse(row.data_value);
        });
        sendJson(response, 200, publicData);
        return;
    }

    if (requestPath === "/api/admin/data" && request.method === "GET") {
        if (!getSession(request)) {
            sendJson(response, 401, { message: "Authentication required." });
            return;
        }
        const rows = database.prepare("SELECT data_key, data_value FROM app_data").all();
        const storedData = {};
        rows.forEach(row => {
            if (ADMIN_DATA_KEYS.has(row.data_key)) storedData[row.data_key] = JSON.parse(row.data_value);
        });
        sendJson(response, 200, storedData);
        return;
    }

    const adminDataMatch = requestPath.match(/^\/api\/admin\/data\/([^/]+)$/);
    if (adminDataMatch && request.method === "PUT") {
        if (!getSession(request)) {
            sendJson(response, 401, { message: "Authentication required." });
            return;
        }
        const dataKey = adminDataMatch[1];
        if (!ADMIN_DATA_KEYS.has(dataKey)) {
            sendJson(response, 404, { message: "Unknown data key." });
            return;
        }
        readJson(request, MAX_DATA_BODY_BYTES).then(value => {
            const serialized = JSON.stringify(value);
            if (serialized === undefined) {
                sendJson(response, 400, { message: "Invalid data." });
                return;
            }
            database.prepare(`
                INSERT INTO app_data (data_key, data_value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(data_key) DO UPDATE SET
                    data_value = excluded.data_value,
                    updated_at = CURRENT_TIMESTAMP
            `).run(dataKey, serialized);
            sendJson(response, 200, { ok: true });
        }).catch(error => {
            sendJson(response, error.statusCode || 400, { message: "Invalid data." });
        });
        return;
    }

    if (requestPath === "/admin-dashboard.html") {
        if (request.method !== "GET" && request.method !== "HEAD") {
            response.writeHead(405, { Allow: "GET, HEAD" }).end("Method not allowed");
            return;
        }
        if (!getSession(request)) {
            response.writeHead(302, {
                Location: "/index.html?admin=login",
                "Cache-Control": "no-store"
            }).end();
            return;
        }
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
        response.writeHead(405, { Allow: "GET, HEAD" }).end("Method not allowed");
        return;
    }

    serveFile(request, response, requestPath);
});

server.listen(PORT, HOST, () => {
    console.log(`SHAIL website running at http://${HOST}:${PORT}`);
});
