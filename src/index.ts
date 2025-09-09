import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";
import { SignJWT, jwtVerify } from "jose";

// This value should be shared between the OpenAuth server Worker and other
// client Workers that you connect to it, so the types and schema validation are
// consistent.
const subjects = createSubjects({
    user: object({
        id: string(),
    }),
});

// --- Start of Configuration ---
// These are the environment variables you need to set in Cloudflare dashboard
const JWT_SECRET = 'YOUR_SECRET_STRING_AT_LEAST_32_CHARS'; // Generate a random, long string
const KV_NAMESPACE_BINDING = 'MY_CONFIG_KV';
const CONFIG_KEY = 'json_config';

// The D1 and KV bindings are defined in `wrangler.toml` or in the Worker settings.
// This example assumes you have an `AUTH_STORAGE` KV namespace and a `AUTH_DB` D1 database.
// --- End of Configuration ---

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // --- 1. Authentication Check ---
        // Try to get and verify a session token from the cookie
        const token = request.headers.get('Cookie')?.split('; ')
                      .find(row => row.startsWith('token='))?.split('=')[1];

        if (token) {
            try {
                const secret = new TextEncoder().encode(JWT_SECRET);
                await jwtVerify(token, secret);
                
                // --- 2. Authenticated Routes ---
                switch (url.pathname) {
                    case '/':
                        return this.handleEditorPage(env, KV_NAMESPACE_BINDING, CONFIG_KEY);
                    case '/publish':
                        return this.handlePublish(request, env, KV_NAMESPACE_BINDING, CONFIG_KEY);
                    case '/api/config':
                        return this.handleApi(env, KV_NAMESPACE_BINDING, CONFIG_KEY);
                    case '/logout':
                        return this.handleLogout();
                    default:
                        return new Response('Not Found', { status: 404 });
                }
            } catch (e) {
                // Token is invalid or expired, log and proceed to login flow
                console.error("JWT verification failed:", e);
            }
        }

        // --- 3. Unauthenticated Login Flow ---
        // All unauthenticated requests are handled by the OpenAuth issuer.
        // It will present the login UI, handle verifications, etc.
        const authServer = issuer({
            storage: CloudflareStorage({
                namespace: env.AUTH_STORAGE,
            }),
            subjects,
            providers: {
                password: PasswordProvider(
                    PasswordUI({
                        // This is where you would email the verification code to the user.
                        // For a demo, it's just logged to the Worker console.
                        sendCode: async (email, code) => {
                            console.log(`Sending code ${code} to ${email}`);
                        },
                        // Customizing the login form text
                        copy: {
                            input_code: "验证码 (请检查Worker日志)",
                        },
                    }),
                ),
            },
            theme: {
                title: "JSON 编辑器",
                primary: "#007bff",
                // favicon and logo properties are omitted for simplicity
            },
            // --- 4. Redirect on Successful Login ---
            success: async (ctx, value) => {
                const userId = await this.getOrCreateUser(env, value.email);
                
                // Create a JWT for the user session
                const secret = new TextEncoder().encode(JWT_SECRET);
                const jwt = await new SignJWT({ 'id': userId })
                    .setProtectedHeader({ alg: 'HS256' })
                    .setIssuedAt()
                    .setExpirationTime('24h')
                    .sign(secret);
                
                // Redirect to the main application page with the JWT in a cookie
                const response = Response.redirect(url.origin, 302);
                response.headers.set(
                    'Set-Cookie',
                    `token=${jwt}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${24 * 60 * 60}`
                );
                
                return response;
            },
        });
        return authServer.fetch(request, env, ctx);
    },

    async getOrCreateUser(env, email) {
        // This function is from the original template to handle D1 user records
        const result = await env.AUTH_DB.prepare(
            `
            INSERT INTO user (email)
            VALUES (?)
            ON CONFLICT (email) DO UPDATE SET email = email
            RETURNING id;
            `,
        )
        .bind(email)
        .first();
        if (!result) {
            throw new Error(`Unable to process user: ${email}`);
        }
        console.log(`Found or created user ${result.id} with email ${email}`);
        return result.id;
    },

    // --- Start of JSON Editor Functionality ---
    async handleEditorPage(env, kvBinding, configKey) {
        if (!env[kvBinding]) {
            const missingKvHtml = `
            <!DOCTYPE html>
            <html lang="zh-CN">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>配置错误</title>
                <style>
                    body { font-family: sans-serif; text-align: center; padding: 50px; }
                    .error-container { border: 1px solid #ff4d4f; background: #fff2f0; color: #cf1322; padding: 20px; border-radius: 8px; max-width: 600px; margin: auto; }
                    h2 { color: #cf1322; }
                    pre { background: #f0f0f0; padding: 10px; border-radius: 4px; text-align: left; overflow-x: auto; }
                </style>
            </head>
            <body>
                <div class="error-container">
                    <h2>配置错误：未找到 KV 绑定</h2>
                    <p>请在 Cloudflare 控制台中完成以下步骤，以关联一个 KV 空间：</p>
                    <ol style="text-align: left;">
                        <li>进入 Worker 页面，选择 <strong>“设置”</strong>。</li>
                        <li>在 <strong>“变量”</strong> 下，找到 <strong>“KV 命名空间绑定”</strong>。</li>
                        <li>点击 <strong>“添加绑定”</strong>，输入变量名 <code>${kvBinding}</code>，并选择一个已创建的 KV 命名空间。</li>
                    </ol>
                </div>
            </body>
            </html>
            `;
            return new Response(missingKvHtml, { headers: { "content-type": "text/html;charset=UTF-8" }, status: 500 });
        }
        let configData = await env[kvBinding].get(configKey);
        if (!configData) {
            configData = '{}';
        }
        const htmlContent = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JSON 配置编辑器</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #f4f7f9; padding: 20px; color: #333; }
        .container { max-width: 800px; margin: auto; background: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .node-row { display: grid; grid-template-columns: 1fr 150px 2fr auto; gap: 15px; align-items: center; margin-bottom: 15px; padding: 10px; border: 1px solid #e0e0e0; border-radius: 5px; }
        .node-row input, .node-row select { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        .node-row button { padding: 8px 12px; background-color: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .node-row button:hover { background-color: #c82333; }
        .controls { display: flex; gap: 15px; margin-top: 20px; }
        .controls button { padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }
        #publishBtn { background-color: #ffc107; color: black; }
        #publishBtn:hover { background-color: #e0a800; }
        #output { background-color: #2e3440; color: #d8dee9; padding: 20px; border-radius: 5px; margin-top: 20px; white-space: pre-wrap; word-wrap: break-word; }
        .footer-controls { display: flex; justify-content: flex-end; align-items: flex-end; margin-top: 20px; }
        #logoutBtn { background-color: #6c757d; color: white; padding: 8px 12px; border: none; border-radius: 4px; cursor: pointer; }
        #logoutBtn:hover { background-color: #5a6268; }
    </style>
</head>
<body>
<div class="container">
    <h2>JSON 配置编辑器</h2>
    <div id="nodes-container"></div>
    <div class="controls">
        <button id="addBtn">添加节点</button>
        <button id="publishBtn">发布</button>
    </div>
    <hr>
    <h3>JSON 输出</h3>
    <pre id="output"></pre>
    <div class="footer-controls">
        <button id="logoutBtn">退出登录</button>
    </div>
</div>
<script>
    const initialConfig = JSON.parse(\`${configData}\`);
    function updateOutput() {
        const data = collectData();
        const output = document.getElementById('output');
        output.textContent = JSON.stringify(data, null, 2);
    }
    function createValueInput(type, value) {
        const input = document.createElement('input');
        input.className = 'value-input';
        const inputValue = (value === undefined || value === null) ? '' : String(value);
        if (type === 'number') {
            input.type = 'number';
            input.value = inputValue;
        } else if (type === 'boolean') {
            input.type = 'checkbox';
            input.checked = (value === true);
        } else {
            input.type = 'text';
            input.value = inputValue;
        }
        input.addEventListener('input', updateOutput);
        return input;
    }
    function addNode(key = '', value, type = 'string') {
        const nodesContainer = document.getElementById('nodes-container');
        const row = document.createElement('div');
        row.className = 'node-row';
        const keyInput = document.createElement('input');
        keyInput.type = 'text';
        keyInput.placeholder = '键 (key)';
        keyInput.value = key;
        keyInput.addEventListener('input', updateOutput);
        const typeSelect = document.createElement('select');
        typeSelect.innerHTML = '<option value="string">文本 (string)</option><option value="number">数字 (number)</option><option value="boolean">布尔 (boolean)</option>';
        typeSelect.value = type;
        const valueInputWrapper = document.createElement('div');
        const valueInput = createValueInput(type, value);
        valueInput.placeholder = '值 (value)';
        valueInputWrapper.appendChild(valueInput);
        const deleteBtn = document.createElement('button');
        deleteBtn.textContent = '删除';
        deleteBtn.onclick = () => {
            nodesContainer.removeChild(row);
            updateOutput();
        };
        typeSelect.onchange = () => {
            const selectedType = typeSelect.value;
            valueInputWrapper.innerHTML = '';
            const newInput = createValueInput(selectedType, null);
            newInput.placeholder = '值 (value)';
            valueInputWrapper.appendChild(newInput);
            updateOutput();
        };
        row.appendChild(keyInput);
        row.appendChild(typeSelect);
        row.appendChild(valueInputWrapper);
        row.appendChild(deleteBtn);
        nodesContainer.appendChild(row);
    }
    function collectData() {
        const jsonObject = {};
        const rows = document.querySelectorAll('.node-row');
        rows.forEach(row => {
            const key = row.querySelector('input[type="text"]').value.trim();
            const type = row.querySelector('select').value;
            let valueElement = row.querySelector('.value-input');
            if (key) {
                let value;
                if (type === 'number') {
                    value = valueElement.value ? Number(valueElement.value) : null;
                } else if (type === 'boolean') {
                    value = valueElement.checked;
                } else {
                    value = valueElement.value;
                }
                jsonObject[key] = value;
            }
        });
        return jsonObject;
    }
    document.addEventListener('DOMContentLoaded', (event) => {
        const nodesContainer = document.getElementById('nodes-container');
        const publishBtn = document.getElementById('publishBtn');
        const addBtn = document.getElementById('addBtn');
        const logoutBtn = document.getElementById('logoutBtn');
        addBtn.addEventListener('click', () => {
            addNode();
            updateOutput();
        });
        publishBtn.addEventListener('click', async () => {
            const data = collectData();
            try {
                const response = await fetch('/publish', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ data: data })
                });
                if (response.ok) {
                    alert('数据已成功发布！');
                } else {
                    alert('发布失败，请检查登录信息或重试。');
                }
            } catch (error) {
                alert('网络请求失败：' + error);
            }
        });
        logoutBtn.addEventListener('click', () => {
            window.location.href = '/logout';
        });
        if (Object.keys(initialConfig).length > 0) {
            for (const key in initialConfig) {
                const value = initialConfig[key];
                const type = typeof value === 'boolean' ? 'boolean' : (typeof value === 'number' ? 'number' : 'string');
                addNode(key, value, type);
            }
        } else {
            addNode();
        }
        updateOutput();
    });
</script>
</body>
</html>
            `;
            return new Response(htmlContent, {
                headers: { "content-type": "text/html;charset=UTF-8" },
            });
        },
    
    async handlePublish(request, env, kvBinding, configKey) {
        try {
            const { data } = await request.json();
            await env[kvBinding].put(configKey, JSON.stringify(data, null, 2));
            return new Response('Config saved.', { status: 200 });
        } catch (e) {
            return new Response('Error saving config: ' + e.message, { status: 500 });
        }
    },
    
    async handleApi(env, kvBinding, configKey) {
        let configData = await env[kvBinding].get(configKey);
        if (!configData) {
            configData = '{}';
        }
        return new Response(configData, {
            headers: {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-store, must-revalidate'
            }
        });
    },

    handleLogout() {
        return new Response('Logged out', {
            status: 302,
            headers: {
                Location: '/',
                'Set-Cookie': 'token=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'
            }
        });
    },
};
