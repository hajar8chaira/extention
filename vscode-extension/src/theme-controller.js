const VALID_THEMES = new Set(['light', 'dark']);

class ThemeController {
  constructor(initialTheme = 'light', persist = () => {}) {
    this.theme = VALID_THEMES.has(initialTheme) ? initialTheme : 'light';
    this.persist = persist;
    this.listeners = new Set();
  }
  getTheme() { return this.theme; }
  setTheme(theme) {
    if (!VALID_THEMES.has(theme) || theme === this.theme) return false;
    this.theme = theme;
    Promise.resolve(this.persist(theme)).catch(() => {});
    for (const listener of this.listeners) listener(theme);
    return true;
  }
  onDidChange(listener) {
    this.listeners.add(listener);
    return { dispose: () => this.listeners.delete(listener) };
  }
  dispose() { this.listeners.clear(); }
}

function themeOverridesCss() {
  return `body.theme-light{color-scheme:light;--vscode-foreground:#424750;--vscode-descriptionForeground:#707782;--vscode-editor-background:#f7f8fa;--vscode-sideBar-background:#f7f8fa;--vscode-panel-border:#d9dde5;--vscode-focusBorder:#4b78cf;--vscode-button-foreground:#fff;--vscode-button-background:#4b78cf;--vscode-button-hoverBackground:#3f69ba;--vscode-button-secondaryForeground:#424750;--vscode-button-secondaryBackground:#e9ebf0;--vscode-badge-foreground:#fff;--vscode-badge-background:#5878bb;--vscode-widget-shadow:rgba(31,41,55,.18);--vscode-errorForeground:#d94b40;--vscode-testing-iconPassed:#4ca866}body.theme-dark{color-scheme:dark}`;
}

module.exports = { ThemeController, themeOverridesCss };
