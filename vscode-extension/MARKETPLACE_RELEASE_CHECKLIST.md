# Marketplace Release Checklist

- [ ] Publisher ID created
- [x] `package.json` publisher set to `ChairaHajar`
- [x] README verified — Secenter lockup and title in place
- [ ] LICENSE validated
- [x] icon validated — `media/branding/secenter-icon-128.png` (128x128), present in the VSIX
- [x] `npm test` green
- [x] `npm run check` green
- [x] VSIX generated — `npm run package:vsix` (the only supported command)
- [x] VSIX installed manually — identity `ChairaHajar.security-center-vscode`
- [ ] no secrets
- [ ] version confirmed
- [ ] Publisher auth configured
- [ ] Preview publication authorized

## Official artefact

One command produces one artefact:

```
npm run package:vsix
```

It packages with `--pre-release` **and** `--baseImagesUrl .../extention/raw/HEAD/vscode-extension`,
and writes `vscode-extension/security-center-vscode-<version>.vsix`. The output name follows
`version` on its own, so nothing here has to be edited at the next release.

Do not package by hand. The two flags are not optional and are easy to forget separately:
without `--pre-release` the Marketplace treats the upload as a stable release, and without
`--baseImagesUrl` vsce rewrites the README images to the repository root — losing the
`vscode-extension/` segment — and the lockup 404s on the Marketplace page.

`security-center-vscode.vsix` at the repository root is a **historical artefact** produced by
the previous version of the script. It is not the release artefact and is not regenerated.

## Known non-blocking warnings

- `vsce` reports that the extension ships many unbundled JavaScript files. This affects
  activation time, not correctness, and is not a publication blocker. Bundling is a
  post-first-release improvement; it is deliberately not attempted before the first
  pre-release.
- `code --install-extension` prints `[DEP0169] DeprecationWarning: url.parse()`. It comes
  from the VS Code CLI, not from this extension.

## Mandatory Stop

Do not run `vsce publish` until the owner has created the Visual Studio Marketplace publisher, provided the exact Publisher ID, configured authentication and explicitly approved publication.
