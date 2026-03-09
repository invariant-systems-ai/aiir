/**
 * AIIR VS Code Extension — verify receipts directly in the editor.
 *
 * Commands:
 *   - aiir.verifyFile       — verify a .json / .aiir.json file
 *   - aiir.verifySelection  — verify selected JSON text
 *
 * This extension embeds the JS verification SDK (../sdks/js/aiir-verify.js)
 * so it works offline with zero external dependencies.
 *
 * @license Apache-2.0
 */

import * as vscode from 'vscode';
import * as crypto from 'crypto';

// ── Constants ─────────────────────────────────────────────────────────
const CORE_KEYS = new Set(['type', 'schema', 'version', 'commit', 'ai_attestation', 'provenance']);
const MAX_DEPTH = 64;
const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+([.+\-][0-9a-zA-Z.+\-]*)?$/;

// ── Canonical JSON (SPEC.md §6) ───────────────────────────────────────

function canonicalJson(obj: unknown, depth = 0): string {
    if (depth > MAX_DEPTH) {
        throw new Error('canonical JSON depth limit exceeded (max 64)');
    }

    if (obj === null) { return 'null'; }
    if (obj === undefined) { return 'null'; }

    if (typeof obj === 'boolean') { return obj ? 'true' : 'false'; }

    if (typeof obj === 'number') {
        if (!isFinite(obj)) { throw new Error('NaN/Infinity not allowed'); }
        return JSON.stringify(obj);
    }

    if (typeof obj === 'string') {
        return JSON.stringify(obj).replace(/[\u0080-\uffff]/g, (ch) => {
            return '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0');
        });
    }

    if (Array.isArray(obj)) {
        return '[' + obj.map(v => canonicalJson(v, depth + 1)).join(',') + ']';
    }

    if (typeof obj === 'object') {
        const o = obj as Record<string, unknown>;
        const keys = Object.keys(o).sort();
        const pairs = keys
            .filter(k => o[k] !== undefined)
            .map(k => canonicalJson(k, depth + 1) + ':' + canonicalJson(o[k], depth + 1));
        return '{' + pairs.join(',') + '}';
    }

    throw new Error('cannot encode type: ' + typeof obj);
}

// ── SHA-256 ───────────────────────────────────────────────────────────

function sha256(str: string): string {
    return crypto.createHash('sha256').update(str, 'utf-8').digest('hex');
}

// ── Verification ──────────────────────────────────────────────────────

interface VerifyResult {
    valid: boolean;
    errors: string[];
}

function verify(receipt: unknown): VerifyResult {
    if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
        return { valid: false, errors: ['receipt is not a dict'] };
    }

    const r = receipt as Record<string, unknown>;

    if (r.type !== 'aiir.commit_receipt') {
        return { valid: false, errors: [`unknown receipt type: '${r.type}'`] };
    }

    if (typeof r.schema !== 'string') {
        return { valid: false, errors: [`unknown schema: ${r.schema}`] };
    }
    if (!r.schema.startsWith('aiir/')) {
        return { valid: false, errors: [`unknown schema: '${r.schema}'`] };
    }

    if (typeof r.version !== 'string' || !VERSION_RE.test(r.version)) {
        return { valid: false, errors: [`invalid version format: '${r.version}'`] };
    }

    const core: Record<string, unknown> = {};
    for (const key of Object.keys(r)) {
        if (CORE_KEYS.has(key)) {
            core[key] = r[key];
        }
    }

    const coreJson = canonicalJson(core);
    const hash = sha256(coreJson);
    const expectedHash = 'sha256:' + hash;
    const expectedId = 'g1-' + hash.slice(0, 32);

    const errors: string[] = [];
    if (!crypto.timingSafeEqual(
        Buffer.from(expectedHash),
        Buffer.from(String(r.content_hash || '').padEnd(expectedHash.length, '\0')).slice(0, expectedHash.length)
    ).valueOf || expectedHash !== r.content_hash) {
        // Fallback to simple comparison (timingSafeEqual requires same length)
        if (expectedHash !== r.content_hash) {
            errors.push('content hash mismatch');
        }
    }
    if (expectedId !== r.receipt_id) {
        errors.push('receipt_id mismatch');
    }

    return { valid: errors.length === 0, errors };
}

// ── Extension entry points ────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
    // Command: verify a file
    const verifyFileCmd = vscode.commands.registerCommand('aiir.verifyFile', async (uri?: vscode.Uri) => {
        const fileUri = uri || vscode.window.activeTextEditor?.document.uri;
        if (!fileUri) {
            vscode.window.showErrorMessage('AIIR: No file selected');
            return;
        }

        try {
            const content = await vscode.workspace.fs.readFile(fileUri);
            const text = Buffer.from(content).toString('utf-8');
            const receipt = JSON.parse(text);
            const result = verify(receipt);
            showResult(result, fileUri.fsPath);
        } catch (e) {
            vscode.window.showErrorMessage(`AIIR: ${(e as Error).message}`);
        }
    });

    // Command: verify selected text
    const verifySelectionCmd = vscode.commands.registerCommand('aiir.verifySelection', () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('AIIR: No active editor');
            return;
        }

        const selection = editor.document.getText(editor.selection);
        if (!selection.trim()) {
            vscode.window.showErrorMessage('AIIR: No text selected');
            return;
        }

        try {
            const receipt = JSON.parse(selection);
            const result = verify(receipt);
            showResult(result, 'selection');
        } catch (e) {
            vscode.window.showErrorMessage(`AIIR: ${(e as Error).message}`);
        }
    });

    context.subscriptions.push(verifyFileCmd, verifySelectionCmd);
}

function showResult(result: VerifyResult, source: string) {
    if (result.valid) {
        vscode.window.showInformationMessage(
            `✅ AIIR: Receipt verified (${source})`
        );
    } else {
        vscode.window.showWarningMessage(
            `❌ AIIR: Verification failed — ${result.errors.join('; ')} (${source})`
        );
    }
}

export function deactivate() {}
