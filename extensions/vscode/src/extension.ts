/**
 * AIIR VS Code Extension — AI Integrity Receipt verification in the editor.
 *
 * Features:
 *   - Status bar indicator showing receipt count + verification status
 *   - Receipt Explorer tree view (sidebar)
 *   - Diagnostics integration (Problems panel)
 *   - Verify receipt from file or selection
 *   - CodeLens on receipt files showing verification status inline
 *   - Auto-discovery of .aiir.json and .receipts/ directories
 *   - File watcher for live receipt updates
 *   - Summary webview dashboard
 *
 * Zero external dependencies — embeds the verification algorithm from SPEC.md §9.
 *
 * @license Apache-2.0
 */

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import * as path from 'path';

// ── Constants ─────────────────────────────────────────────────────────
const CORE_KEYS = new Set(['type', 'schema', 'version', 'commit', 'ai_attestation', 'provenance']);
const MAX_DEPTH = 64;
const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+([.+\-][0-9a-zA-Z.+\-]*)?$/;

// ── Canonical JSON (SPEC.md §6) ───────────────────────────────────────

function canonicalJson(obj: unknown, depth = 0): string {
    if (depth > MAX_DEPTH) {
        throw new Error('canonical JSON depth limit exceeded (max 64)');
    }

    if (obj === null || obj === undefined) { return 'null'; }
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

interface ReceiptData {
    type?: string;
    schema?: string;
    version?: string;
    receipt_id?: string;
    content_hash?: string;
    timestamp?: string;
    commit?: {
        sha?: string;
        author?: { name?: string; email?: string };
        committer?: { name?: string; email?: string };
        subject?: string;
        files_changed?: number;
        files?: string[];
    };
    ai_attestation?: {
        ai_authored?: boolean;
        signals?: Array<{ type?: string; source?: string; value?: string }>;
        signal_count?: number;
    };
    provenance?: {
        generator?: string;
        repository?: string;
    };
    extensions?: Record<string, unknown>;
    [key: string]: unknown;
}

function verify(receipt: unknown): VerifyResult {
    if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
        return { valid: false, errors: ['receipt is not a dict'] };
    }

    const r = receipt as Record<string, unknown>;

    if (r.type !== 'aiir.commit_receipt') {
        return { valid: false, errors: [`unknown receipt type: '${r.type}'`] };
    }

    if (typeof r.schema !== 'string' || !r.schema.startsWith('aiir/')) {
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
    if (expectedHash !== r.content_hash) {
        errors.push('content hash mismatch');
    }
    if (expectedId !== r.receipt_id) {
        errors.push('receipt_id mismatch');
    }

    return { valid: errors.length === 0, errors };
}

// ── Receipt Discovery ─────────────────────────────────────────────────

async function discoverReceipts(): Promise<vscode.Uri[]> {
    const patterns = [
        '**/*.aiir.json',
        '**/.receipts/*.json',
        '**/.aiir-receipts/*.json',
        '**/.aiir/*.json',
    ];

    const uris: vscode.Uri[] = [];
    for (const pattern of patterns) {
        const found = await vscode.workspace.findFiles(pattern, '**/node_modules/**', 500);
        uris.push(...found);
    }

    // Deduplicate
    const seen = new Set<string>();
    return uris.filter(u => {
        if (seen.has(u.fsPath)) { return false; }
        seen.add(u.fsPath);
        return true;
    });
}

async function loadReceipt(uri: vscode.Uri): Promise<ReceiptData | null> {
    try {
        const content = await vscode.workspace.fs.readFile(uri);
        const text = Buffer.from(content).toString('utf-8');
        const parsed = JSON.parse(text);
        if (parsed && typeof parsed === 'object' && parsed.type === 'aiir.commit_receipt') {
            return parsed as ReceiptData;
        }
    } catch {
        // Not a valid receipt — skip
    }
    return null;
}

// ── Receipt Explorer Tree View ────────────────────────────────────────

class ReceiptTreeItem extends vscode.TreeItem {
    constructor(
        public readonly receipt: ReceiptData,
        public readonly uri: vscode.Uri,
        public readonly result: VerifyResult,
    ) {
        const shortId = receipt.receipt_id?.slice(0, 16) || 'unknown';
        const commitShort = receipt.commit?.sha?.slice(0, 8) || '?';
        const isAI = receipt.ai_attestation?.ai_authored ?? false;

        super(
            `${result.valid ? '✅' : '❌'} ${commitShort} ${isAI ? '🤖' : '👤'} ${shortId}`,
            vscode.TreeItemCollapsibleState.Collapsed,
        );

        this.tooltip = new vscode.MarkdownString(
            `**Receipt:** \`${receipt.receipt_id}\`\n\n` +
            `**Commit:** \`${receipt.commit?.sha}\`\n\n` +
            `**Subject:** ${receipt.commit?.subject || '—'}\n\n` +
            `**AI Authored:** ${isAI ? 'Yes' : 'No'}\n\n` +
            `**Signals:** ${receipt.ai_attestation?.signal_count ?? 0}\n\n` +
            `**Status:** ${result.valid ? '✅ Verified' : '❌ ' + result.errors.join(', ')}\n\n` +
            `**Timestamp:** ${receipt.timestamp || '—'}`
        );

        this.iconPath = new vscode.ThemeIcon(
            result.valid ? 'verified-filled' : 'error',
            result.valid
                ? new vscode.ThemeColor('charts.green')
                : new vscode.ThemeColor('charts.red'),
        );

        this.contextValue = result.valid ? 'receipt-valid' : 'receipt-invalid';

        this.command = {
            command: 'vscode.open',
            title: 'Open Receipt',
            arguments: [uri],
        };
    }
}

class ReceiptDetailItem extends vscode.TreeItem {
    constructor(label: string, value: string, icon?: string) {
        super(`${label}: ${value}`, vscode.TreeItemCollapsibleState.None);
        if (icon) {
            this.iconPath = new vscode.ThemeIcon(icon);
        }
    }
}

class ReceiptExplorerProvider implements vscode.TreeDataProvider<ReceiptTreeItem | ReceiptDetailItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private receipts: Array<{ receipt: ReceiptData; uri: vscode.Uri; result: VerifyResult }> = [];

    async refresh(): Promise<void> {
        const uris = await discoverReceipts();
        this.receipts = [];

        for (const uri of uris) {
            const receipt = await loadReceipt(uri);
            if (receipt) {
                const result = verify(receipt);
                this.receipts.push({ receipt, uri, result });
            }
        }

        // Sort: failed first, then by timestamp descending
        this.receipts.sort((a, b) => {
            if (a.result.valid !== b.result.valid) {
                return a.result.valid ? 1 : -1;
            }
            return (b.receipt.timestamp || '').localeCompare(a.receipt.timestamp || '');
        });

        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: ReceiptTreeItem | ReceiptDetailItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: ReceiptTreeItem | ReceiptDetailItem): (ReceiptTreeItem | ReceiptDetailItem)[] {
        if (!element) {
            return this.receipts.map(r => new ReceiptTreeItem(r.receipt, r.uri, r.result));
        }

        if (element instanceof ReceiptTreeItem) {
            const r = element.receipt;
            const details: ReceiptDetailItem[] = [];

            details.push(new ReceiptDetailItem('SHA', r.commit?.sha?.slice(0, 12) || '?', 'git-commit'));
            details.push(new ReceiptDetailItem('Subject', r.commit?.subject || '—', 'comment'));
            details.push(new ReceiptDetailItem('Author', r.commit?.author?.name || '—', 'person'));
            details.push(new ReceiptDetailItem('AI Authored', r.ai_attestation?.ai_authored ? 'Yes 🤖' : 'No 👤', 'hubot'));
            details.push(new ReceiptDetailItem('Signals', String(r.ai_attestation?.signal_count ?? 0), 'search'));
            details.push(new ReceiptDetailItem('Files Changed', String(r.commit?.files_changed ?? 0), 'file'));
            details.push(new ReceiptDetailItem('Generator', r.provenance?.generator || '—', 'tools'));
            details.push(new ReceiptDetailItem('Timestamp', r.timestamp || '—', 'calendar'));

            if (r.extensions && Object.keys(r.extensions).length > 0) {
                if (r.extensions.agent_attestation) {
                    const agent = r.extensions.agent_attestation as Record<string, string>;
                    details.push(new ReceiptDetailItem('Agent Tool', agent.tool_id || '—', 'robot'));
                    if (agent.model_class) {
                        details.push(new ReceiptDetailItem('Model', agent.model_class, 'symbol-class'));
                    }
                }
                if (r.extensions.sigstore) {
                    details.push(new ReceiptDetailItem('Signed', '✍️ Sigstore', 'lock'));
                }
            }

            return details;
        }

        return [];
    }

    getStats(): { total: number; valid: number; invalid: number; aiAuthored: number } {
        const total = this.receipts.length;
        const valid = this.receipts.filter(r => r.result.valid).length;
        const invalid = total - valid;
        const aiAuthored = this.receipts.filter(r => r.receipt.ai_attestation?.ai_authored).length;
        return { total, valid, invalid, aiAuthored };
    }
}

// ── Status Bar ────────────────────────────────────────────────────────

class StatusBarManager {
    private item: vscode.StatusBarItem;

    constructor() {
        this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
        this.item.command = 'aiir.showSummary';
        this.item.name = 'AIIR Receipts';
    }

    update(stats: { total: number; valid: number; invalid: number; aiAuthored: number }) {
        if (stats.total === 0) {
            this.item.text = '$(shield) AIIR: No receipts';
            this.item.tooltip = 'No AIIR receipts found in workspace';
            this.item.backgroundColor = undefined;
        } else if (stats.invalid > 0) {
            this.item.text = `$(shield) AIIR: ${stats.invalid}/${stats.total} ❌`;
            this.item.tooltip = new vscode.MarkdownString(
                `**AIIR Receipt Summary**\n\n` +
                `| Metric | Value |\n|---|---|\n` +
                `| Total Receipts | ${stats.total} |\n` +
                `| ✅ Verified | ${stats.valid} |\n` +
                `| ❌ Failed | ${stats.invalid} |\n` +
                `| 🤖 AI-Authored | ${stats.aiAuthored} |\n` +
                `| AI % | ${stats.total > 0 ? Math.round(stats.aiAuthored / stats.total * 100) : 0}% |`
            );
            this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        } else {
            this.item.text = `$(verified-filled) AIIR: ${stats.total} ✅`;
            this.item.tooltip = new vscode.MarkdownString(
                `**AIIR Receipt Summary**\n\n` +
                `| Metric | Value |\n|---|---|\n` +
                `| Total Receipts | ${stats.total} |\n` +
                `| ✅ All Verified | ${stats.valid} |\n` +
                `| 🤖 AI-Authored | ${stats.aiAuthored} |\n` +
                `| AI % | ${stats.total > 0 ? Math.round(stats.aiAuthored / stats.total * 100) : 0}% |`
            );
            this.item.backgroundColor = undefined;
        }

        this.item.show();
    }

    dispose() {
        this.item.dispose();
    }
}

// ── Diagnostics ───────────────────────────────────────────────────────

function updateDiagnostics(
    diagnosticCollection: vscode.DiagnosticCollection,
    uri: vscode.Uri,
    receipt: ReceiptData,
    result: VerifyResult,
) {
    if (result.valid) {
        diagnosticCollection.delete(uri);
        return;
    }

    const diagnostics: vscode.Diagnostic[] = result.errors.map(error => {
        const range = new vscode.Range(0, 0, 0, 1);
        const diag = new vscode.Diagnostic(
            range,
            `AIIR: ${error}`,
            vscode.DiagnosticSeverity.Error,
        );
        diag.source = 'AIIR';
        diag.code = 'receipt-integrity';
        return diag;
    });

    diagnosticCollection.set(uri, diagnostics);
}

// ── CodeLens Provider ─────────────────────────────────────────────────

class ReceiptCodeLensProvider implements vscode.CodeLensProvider {
    private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
    readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

    provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
        if (!document.fileName.endsWith('.aiir.json') &&
            !document.uri.fsPath.includes('.receipts') &&
            !document.uri.fsPath.includes('.aiir')) {
            return [];
        }

        try {
            const receipt = JSON.parse(document.getText());
            if (receipt?.type !== 'aiir.commit_receipt') { return []; }

            const result = verify(receipt);
            const range = new vscode.Range(0, 0, 0, 0);
            const lenses: vscode.CodeLens[] = [];

            if (result.valid) {
                lenses.push(new vscode.CodeLens(range, {
                    title: '✅ Receipt Verified — integrity intact',
                    command: 'aiir.verifyFile',
                }));
            } else {
                lenses.push(new vscode.CodeLens(range, {
                    title: `❌ Receipt INVALID — ${result.errors.join(', ')}`,
                    command: 'aiir.verifyFile',
                }));
            }

            // Show key receipt info inline
            const isAI = receipt.ai_attestation?.ai_authored;
            const signals = receipt.ai_attestation?.signal_count ?? 0;
            const sha = receipt.commit?.sha?.slice(0, 8) || '?';
            lenses.push(new vscode.CodeLens(range, {
                title: `${isAI ? '🤖 AI-authored' : '👤 Human-authored'} · ${signals} signals · commit ${sha}`,
                command: '',
            }));

            if (receipt.extensions?.sigstore) {
                lenses.push(new vscode.CodeLens(range, {
                    title: '🔐 Sigstore signed',
                    command: '',
                }));
            }

            return lenses;
        } catch {
            return [];
        }
    }
}

// ── File System Watcher ───────────────────────────────────────────────

function createReceiptWatcher(
    explorer: ReceiptExplorerProvider,
    statusBar: StatusBarManager,
    diagnosticCollection: vscode.DiagnosticCollection,
): vscode.FileSystemWatcher {
    const watcher = vscode.workspace.createFileSystemWatcher('**/*.{aiir.json,json}');

    const handleChange = async (uri: vscode.Uri) => {
        if (!uri.fsPath.includes('.aiir') && !uri.fsPath.includes('.receipts') && !uri.fsPath.endsWith('.aiir.json')) {
            return;
        }
        const receipt = await loadReceipt(uri);
        if (receipt) {
            const result = verify(receipt);
            updateDiagnostics(diagnosticCollection, uri, receipt, result);
        }
        await explorer.refresh();
        statusBar.update(explorer.getStats());
    };

    watcher.onDidCreate(handleChange);
    watcher.onDidChange(handleChange);
    watcher.onDidDelete(async () => {
        await explorer.refresh();
        statusBar.update(explorer.getStats());
    });

    return watcher;
}

// ── Extension Activation ──────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
    // Diagnostics collection
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('aiir');
    context.subscriptions.push(diagnosticCollection);

    // Tree view provider
    const explorer = new ReceiptExplorerProvider();
    const treeView = vscode.window.createTreeView('aiir.receiptExplorer', {
        treeDataProvider: explorer,
        showCollapseAll: true,
    });
    context.subscriptions.push(treeView);

    // Status bar
    const statusBar = new StatusBarManager();
    context.subscriptions.push({ dispose: () => statusBar.dispose() });

    // CodeLens
    const codeLensProvider = new ReceiptCodeLensProvider();
    context.subscriptions.push(
        vscode.languages.registerCodeLensProvider(
            [
                { pattern: '**/*.aiir.json' },
                { pattern: '**/.receipts/*.json' },
                { pattern: '**/.aiir-receipts/*.json' },
                { pattern: '**/.aiir/*.json' },
            ],
            codeLensProvider,
        ),
    );

    // File watcher
    const watcher = createReceiptWatcher(explorer, statusBar, diagnosticCollection);
    context.subscriptions.push(watcher);

    // ── Commands ──────────────────────────────────────────────────────

    // Verify a file
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
            updateDiagnostics(diagnosticCollection, fileUri, receipt, result);
            showResult(result, path.basename(fileUri.fsPath));
        } catch (e) {
            vscode.window.showErrorMessage(`AIIR: ${(e as Error).message}`);
        }
    });

    // Verify selected text
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

    // Refresh receipts
    const refreshCmd = vscode.commands.registerCommand('aiir.refresh', async () => {
        await explorer.refresh();
        statusBar.update(explorer.getStats());
        vscode.window.showInformationMessage('AIIR: Receipts refreshed');
    });

    // Show summary dashboard
    const showSummaryCmd = vscode.commands.registerCommand('aiir.showSummary', async () => {
        const stats = explorer.getStats();
        const aiPercent = stats.total > 0 ? Math.round(stats.aiAuthored / stats.total * 100) : 0;

        const panel = vscode.window.createWebviewPanel(
            'aiir.summary',
            'AIIR Receipt Summary',
            vscode.ViewColumn.One,
            { enableScripts: false },
        );

        panel.webview.html = getSummaryHtml(stats, aiPercent);
    });

    // Verify all receipts in workspace
    const verifyAllCmd = vscode.commands.registerCommand('aiir.verifyAll', async () => {
        await explorer.refresh();
        const stats = explorer.getStats();
        statusBar.update(stats);

        if (stats.total === 0) {
            vscode.window.showInformationMessage('AIIR: No receipts found in workspace');
        } else if (stats.invalid === 0) {
            vscode.window.showInformationMessage(`AIIR: All ${stats.total} receipts verified ✅`);
        } else {
            vscode.window.showWarningMessage(`AIIR: ${stats.invalid}/${stats.total} receipts FAILED verification ❌`);
        }
    });

    context.subscriptions.push(verifyFileCmd, verifySelectionCmd, refreshCmd, showSummaryCmd, verifyAllCmd);

    // ── Initial scan ──────────────────────────────────────────────────
    explorer.refresh().then(() => {
        statusBar.update(explorer.getStats());
    });
}

// ── UI Helpers ────────────────────────────────────────────────────────

function showResult(result: VerifyResult, source: string) {
    if (result.valid) {
        vscode.window.showInformationMessage(`✅ AIIR: Receipt verified (${source})`);
    } else {
        vscode.window.showWarningMessage(`❌ AIIR: Verification failed — ${result.errors.join('; ')} (${source})`);
    }
}

function getSummaryHtml(
    stats: { total: number; valid: number; invalid: number; aiAuthored: number },
    aiPercent: number,
): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AIIR Receipt Summary</title>
    <style>
        body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 20px; }
        h1 { font-size: 1.4em; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; max-width: 500px; }
        .card { background: var(--vscode-editor-background); border: 1px solid var(--vscode-panel-border);
                border-radius: 8px; padding: 16px; text-align: center; }
        .card .value { font-size: 2em; font-weight: bold; }
        .card .label { font-size: 0.85em; opacity: 0.7; margin-top: 4px; }
        .valid .value { color: var(--vscode-testing-iconPassed); }
        .invalid .value { color: var(--vscode-testing-iconFailed); }
        .bar { height: 8px; border-radius: 4px; background: var(--vscode-progressBar-background);
               margin-top: 20px; max-width: 500px; }
        .bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
        .bar-label { font-size: 0.85em; opacity: 0.7; margin-top: 6px; }
    </style>
</head>
<body>
    <h1>🛡️ AIIR Receipt Summary</h1>
    <div class="grid">
        <div class="card">
            <div class="value">${stats.total}</div>
            <div class="label">Total Receipts</div>
        </div>
        <div class="card valid">
            <div class="value">${stats.valid}</div>
            <div class="label">✅ Verified</div>
        </div>
        <div class="card invalid">
            <div class="value">${stats.invalid}</div>
            <div class="label">❌ Failed</div>
        </div>
        <div class="card">
            <div class="value">${stats.aiAuthored}</div>
            <div class="label">🤖 AI-Authored</div>
        </div>
    </div>
    <div class="bar">
        <div class="bar-fill" style="width:${aiPercent}%; background: var(--vscode-charts-blue);"></div>
    </div>
    <div class="bar-label">${aiPercent}% AI-authored commits</div>
</body>
</html>`;
}

export function deactivate() {}
