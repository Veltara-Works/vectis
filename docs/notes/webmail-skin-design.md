# Webmail Skin Customization — Design Notes

## Approach: CSS Variable Overrides on Elastic

Roundcube's **Elastic** skin uses CSS custom properties (variables) for all colours,
spacing, and layout parameters. Rather than forking the skin, we inject a custom
stylesheet that overrides these variables. This approach:

- **Survives Roundcube upgrades** — no patched files to re-merge
- **Minimal maintenance** — single `styles.css` file
- **Full control** — every colour, spacing, and layout element is customisable

## Current Overrides (docker/webmail/skin/styles.css)

| Variable | Default (Elastic) | Vectis Override | Purpose |
|---|---|---|---|
| `--color-main` | `#37beff` | `#3b82f6` | Primary brand colour |
| `--color-main-dark` | `#178acc` | `#2563eb` | Hover/active states |
| `--layout-header-background` | `#f4f4f4` | `#0f172a` | Sidebar/toolbar background |
| `--color-list-selected` | default | `#dbeafe` | Selected message highlight |

## Branding Elements

1. **Login screen title**: Font overrides for modern sans-serif
2. **Footer**: Hide Roundcube.net link, add "Powered by Vectis Mail"
3. **Favicon**: Mount custom favicon at `/var/www/html/skins/elastic/images/favicon.ico`

## Future Enhancements

### Per-Tenant Branding (Phase 4 — Multi-Tenant)
- Store brand colours per tenant in database
- Generate CSS variables dynamically via Go template
- Inject via `<style>` tag in custom skin's `meta.json`

### Custom Login Page
- Replace Roundcube's login form with Vectis-styled page
- Option to redirect to Vectis admin UI for SSO flow
- Add OIDC login buttons alongside IMAP auth

### Dark Mode
- Elastic supports `prefers-color-scheme: dark` natively
- Add Vectis dark mode palette using `@media (prefers-color-scheme: dark)` overrides

## Mounting the Skin

The custom CSS is mounted as a read-only volume into the Roundcube container:

```yaml
volumes:
  - webmail-skin:/var/roundcube/skins/vectis:ro
```

Roundcube loads custom CSS from skins via the `skin_include_php` mechanism.
For simple CSS overrides, we inject via the Roundcube config:

```php
$config['skin'] = 'elastic';
// Custom CSS loaded via HTTP (served by nginx alongside Roundcube)
```

Alternatively, mount `styles.css` directly into Elastic's `extra` directory.
