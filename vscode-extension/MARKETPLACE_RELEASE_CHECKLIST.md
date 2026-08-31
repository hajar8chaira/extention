# Marketplace Release Checklist

- [ ] Publisher ID created
- [x] `package.json` publisher set to `ChairaHajar`
- [x] README verified — Secenter lockup and title in place
- [ ] LICENSE validated
- [x] icon validated — `media/branding/secenter-icon-128.png` (128x128), present in the VSIX
- [x] `npm test` green
- [x] `npm run check` green
- [x] VSIX generated — `security-center-vscode-0.9.0.vsix` (pre-release)
- [x] VSIX installed manually — identity `ChairaHajar.security-center-vscode`
- [ ] no secrets
- [ ] version confirmed
- [ ] Publisher auth configured
- [ ] Preview publication authorized

## Mandatory Stop

Do not run `vsce publish` until the owner has created the Visual Studio Marketplace publisher, provided the exact Publisher ID, configured authentication and explicitly approved publication.
