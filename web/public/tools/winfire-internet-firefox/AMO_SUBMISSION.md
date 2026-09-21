# Firefox Add-ons submission checklist

- Submit the signed package with the privacy policy URL pointing to the deployed WinFIRE privacy
  notice.
- Keep the `websiteActivity` data collection declaration synchronized with the extension's
  disclosure and the server's host/path retention setting.
- Verify host permission consent, private browsing exclusion, revocation, offline queue limits,
  and the Firefox version listed in `strict_min_version` before publication.
- Use the deployed extension ID in `EXTENSION_ORIGINS` after AMO assigns the production origin.
