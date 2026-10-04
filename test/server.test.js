"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

const root = path.resolve(__dirname, "..");

test("inline page scripts compile", () => {
    for (const fileName of ["index.html", "admin-dashboard.html"]) {
        const html = fs.readFileSync(path.join(root, fileName), "utf8");
        const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)]
            .map(match => match[1])
            .filter(script => script.trim());
        assert.ok(scripts.length > 0, `${fileName} should contain its inline bootstrap scripts`);
        scripts.forEach((script, index) => {
            assert.doesNotThrow(() => new Function(script), `${fileName} inline script ${index + 1}`);
        });
    }
});

function startServer(options) {
    const child = spawn(process.execPath, [path.join(root, "server.js")], {
        cwd: root,
        env: { ...process.env, ...options },
        stdio: ["ignore", "pipe", "pipe"]
    });

    const ready = new Promise((resolve, reject) => {
        let output = "";
        const timer = setTimeout(() => reject(new Error(`Server startup timed out: ${output}`)), 10000);
        child.stdout.on("data", chunk => {
            output += chunk;
            if (output.includes("website running at")) {
                clearTimeout(timer);
                resolve();
            }
        });
        child.stderr.on("data", chunk => { output += chunk; });
        child.once("error", error => {
            clearTimeout(timer);
            reject(error);
        });
        child.once("exit", code => {
            if (code !== 0) {
                clearTimeout(timer);
                reject(new Error(`Server exited with ${code}: ${output}`));
            }
        });
    });

    return { child, ready };
}

async function stopServer(child) {
    if (!child || child.exitCode !== null) return;
    const exited = new Promise(resolve => child.once("exit", resolve));
    child.kill();
    await exited;
}

test("admin auth and shared SQLite data survive server restart", async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "shail-server-test-"));
    const port = 18000 + Math.floor(Math.random() * 10000);
    const password = `Test-only-${crypto.randomBytes(24).toString("hex")}`;
    const baseUrl = `http://127.0.0.1:${port}`;
    const environment = {
        ADMIN_PASSWORD: password,
        HOST: "127.0.0.1",
        PORT: String(port),
        DATA_DIR: dataDir
    };
    let running = startServer(environment);

    t.after(async () => {
        await stopServer(running?.child);
        fs.rmSync(dataDir, { recursive: true, force: true });
    });

    await running.ready;

    const direct = await fetch(`${baseUrl}/admin-dashboard.html`, { redirect: "manual" });
    assert.equal(direct.status, 302);
    assert.equal(direct.headers.get("location"), "/index.html?admin=login");

    const privateDataWithoutLogin = await fetch(`${baseUrl}/api/admin/data`);
    assert.equal(privateDataWithoutLogin.status, 401);

    const wrongLogin = await fetch(`${baseUrl}/api/admin/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "Nitya", password: "incorrect" })
    });
    assert.equal(wrongLogin.status, 401);

    const login = await fetch(`${baseUrl}/api/admin/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "Nitya", password })
    });
    assert.equal(login.status, 200);
    const cookie = login.headers.get("set-cookie")?.split(";")[0];
    assert.ok(cookie);

    const dashboard = await fetch(`${baseUrl}/admin-dashboard.html`, { headers: { Cookie: cookie } });
    assert.equal(dashboard.status, 200);

    const products = [{ id: 91, name: "SQLite sync test", category: "Glass", price: 100 }];
    const save = await fetch(`${baseUrl}/api/admin/data/shail_admin_products`, {
        method: "PUT",
        headers: { Cookie: cookie, "Content-Type": "application/json" },
        body: JSON.stringify(products)
    });
    assert.equal(save.status, 200);

    const publicResponse = await fetch(`${baseUrl}/api/site-data`);
    const publicData = await publicResponse.json();
    assert.equal(publicData.shail_admin_products[0].name, "SQLite sync test");
    assert.equal("shail_billing_records" in publicData, false);
    assert.equal((await fetch(`${baseUrl}/data/shail.sqlite`)).status, 404);

    await stopServer(running.child);
    running = startServer(environment);
    await running.ready;

    const restoredSession = await fetch(`${baseUrl}/api/admin/session`, { headers: { Cookie: cookie } });
    assert.equal(restoredSession.status, 200);

    const restoredData = await fetch(`${baseUrl}/api/admin/data`, { headers: { Cookie: cookie } });
    assert.equal((await restoredData.json()).shail_admin_products[0].name, "SQLite sync test");

    const logout = await fetch(`${baseUrl}/api/admin/logout`, {
        method: "POST",
        headers: { Cookie: cookie }
    });
    assert.equal(logout.status, 200);

    const revokedSession = await fetch(`${baseUrl}/api/admin/session`, { headers: { Cookie: cookie } });
    assert.equal(revokedSession.status, 401);
});
