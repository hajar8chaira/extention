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
  return `
    body {
      --sc-bg: var(--vscode-editor-background, #1e1e1e);
      --sc-surface: var(--vscode-sideBar-background, var(--vscode-editor-background, #252526));
      --sc-surface-secondary: var(--vscode-editor-inactiveSelectionBackground, #2d2d2d);
      --sc-surface-hover: var(--vscode-list-hoverBackground, rgba(255,255,255,0.06));
      
      --sc-text: var(--vscode-foreground, #cccccc);
      --sc-text-secondary: var(--vscode-descriptionForeground, #858585);
      --sc-text-muted: var(--vscode-descriptionForeground, #858585);
      
      --sc-border: var(--vscode-panel-border, #3c3c3c);
      --sc-border-strong: var(--vscode-widget-border, #454545);
      
      --sc-input-bg: var(--vscode-input-background, #2d2d2d);
      --sc-input-text: var(--vscode-input-foreground, #cccccc);
      --sc-input-border: var(--vscode-input-border, #3c3c3c);
      --sc-input-placeholder: var(--vscode-input-placeholderForeground, #858585);
      
      --sc-primary: var(--vscode-button-background, #0e639c);
      --sc-primary-hover: var(--vscode-button-hoverBackground, #1177bb);
      --sc-primary-text: var(--vscode-button-foreground, #ffffff);
      
      --sc-success: #4ca866;
      --sc-success-bg: rgba(76, 168, 102, 0.12);
      --sc-warning: #e3c036;
      --sc-warning-bg: rgba(227, 192, 54, 0.12);
      --sc-danger: #ff7b72;
      --sc-danger-bg: rgba(217, 75, 64, 0.12);
      --sc-info: #007acc;
      --sc-info-bg: rgba(0, 122, 204, 0.12);
      
      --sc-button-secondary-bg: var(--vscode-button-secondaryBackground, #3a3d41);
      --sc-button-secondary-fg: var(--vscode-button-secondaryForeground, #ffffff);
    }
    
    body.theme-light {
      color-scheme: light;
      
      --sc-bg: #f3f4f6;
      --sc-surface: #ffffff;
      --sc-surface-secondary: #edf0f4;
      --sc-surface-hover: rgba(0, 0, 0, 0.04);
      
      --sc-text: #424750;
      --sc-text-secondary: #707782;
      --sc-text-muted: #858e9c;
      
      --sc-border: #d9dde5;
      --sc-border-strong: #cfd4dc;
      
      --sc-input-bg: #ffffff;
      --sc-input-text: #353a42;
      --sc-input-border: #cfd4dc;
      --sc-input-placeholder: #858e9c;
      
      --sc-primary: #4b78cf;
      --sc-primary-hover: #3f69ba;
      --sc-primary-text: #ffffff;
      
      --sc-success: #28a745;
      --sc-success-bg: rgba(40, 167, 69, 0.06);
      --sc-warning: #d29922;
      --sc-warning-bg: rgba(210, 153, 34, 0.06);
      --sc-danger: #d94b40;
      --sc-danger-bg: rgba(217, 75, 64, 0.06);
      --sc-info: #4b78cf;
      --sc-info-bg: rgba(75, 120, 207, 0.06);
      
      --sc-button-secondary-bg: #e9ebf0;
      --sc-button-secondary-fg: #424750;
    }
    
    body.theme-dark {
      color-scheme: dark;
      
      --sc-bg: var(--vscode-editor-background, #1e1e1e);
      --sc-surface: var(--vscode-sideBar-background, var(--vscode-editor-background, #252526));
      --sc-surface-secondary: var(--vscode-editor-inactiveSelectionBackground, #2d2d2d);
      --sc-surface-hover: var(--vscode-list-hoverBackground, rgba(255,255,255,0.06));
      
      --sc-text: var(--vscode-foreground, #cccccc);
      --sc-text-secondary: var(--vscode-descriptionForeground, #858585);
      --sc-text-muted: var(--vscode-descriptionForeground, #858585);
      
      --sc-border: var(--vscode-panel-border, #3c3c3c);
      --sc-border-strong: var(--vscode-widget-border, #454545);
      
      --sc-input-bg: var(--vscode-input-background, #2d2d2d);
      --sc-input-text: var(--vscode-input-foreground, #cccccc);
      --sc-input-border: var(--vscode-input-border, #3c3c3c);
      --sc-input-placeholder: var(--vscode-input-placeholderForeground, #858585);
      
      --sc-primary: var(--vscode-button-background, #0e639c);
      --sc-primary-hover: var(--vscode-button-hoverBackground, #1177bb);
      --sc-primary-text: var(--vscode-button-foreground, #ffffff);
      
      --sc-success: #4ca866;
      --sc-success-bg: rgba(76, 168, 102, 0.12);
      --sc-warning: #e3c036;
      --sc-warning-bg: rgba(227, 192, 54, 0.12);
      --sc-danger: #ff7b72;
      --sc-danger-bg: rgba(217, 75, 64, 0.12);
      --sc-info: #007acc;
      --sc-info-bg: rgba(0, 122, 204, 0.12);
      
      --sc-button-secondary-bg: var(--vscode-button-secondaryBackground, #3a3d41);
      --sc-button-secondary-fg: var(--vscode-button-secondaryForeground, #ffffff);
    }
  `;
}

module.exports = { ThemeController, themeOverridesCss };
