=== Felix Connector ===
Contributors: agentfelix
Tags: woocommerce, customer service, ai, automation, ecommerce
Requires at least: 6.0
Tested up to: 6.5
Requires PHP: 8.1
Stable tag: 0.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Connect your WooCommerce store to Felix (agentfelix.ai) for autonomous customer service and store operations.

== Description ==

Felix is an AI-powered customer service and executive operating partner for WooCommerce brands. This connector plugin links your store to Felix so it can look up orders, manage coupons, process refunds, and handle customer inquiries — all through a secure outbound connection that works behind any firewall.

**How it works:**

Your store initiates all communication to Felix — Felix never makes inbound requests to your store. This means the connector works behind any host firewall, captcha system, or security layer (SiteGround Anti-Bot, Cloudflare, Wordfence, and others).

The connector runs automatically via WordPress's built-in scheduler (which runs whenever people visit your site) — no server configuration needed. It activates on the first page visit after pairing and continues running in the background as long as your site receives traffic.

Felix executes typed, validated commands only. There is no generic executor — every action is a specific, hand-written handler. You can disable any command family at any time from the plugin settings.

**What Felix can do:**

* Look up orders, products, coupons, and subscriptions
* Update order status and shipping addresses
* Create comp/free orders
* Manage coupons
* Process refunds (requires explicit approval per refund)
* Sync order and product data for analysis

**Security:**

* Outbound-only communication — your store's firewall is never bypassed
* Per-command-family kill switches in plugin settings
* Every command is Ed25519-signed and verified
* Refunds and money-moving actions require explicit human approval
* Full audit log of every command executed

== Installation ==

1. Install the plugin via WordPress admin (Plugins → Add New → Upload Plugin) or download the zip.
2. Activate the plugin.
3. Go to WooCommerce → Felix Connector in your WordPress admin.
4. Enter the pairing code from your Felix dashboard at [agentfelix.ai](https://agentfelix.ai).
5. Done! The connector activates automatically within a few minutes.

No server configuration or SSH access required. The connector runs via WordPress's built-in scheduler (which runs automatically whenever people visit your site) and activates on the first page visit after pairing.

== Frequently Asked Questions ==

= Is this plugin safe? =

Yes. Felix can only execute specific, typed commands (look up orders, update status, process refunds, etc.). There is no generic executor. Every command is signed and verified. You can disable any command family from the plugin settings at any time.

= Does Felix make requests to my store? =

No. Your store contacts Felix — never the other way around. This is by design: it makes the connector invisible to your host's firewall, captcha, or security layer.

= How does Felix authenticate? =

At pairing, the plugin generates an Ed25519 keypair. The private key never leaves your store. Felix signs every command with its own key, and the plugin verifies each signature before executing. Both sides authenticate each other.

= Do I need to set up a scheduled task? =

No. The connector runs automatically via WordPress's built-in scheduler, which fires whenever people visit your site. In rare cases (very low-traffic sites, or DISABLE_WP_CRON set in wp-config.php), a scheduled task — also called a cron job — may be needed. The plugin will detect this and show step-by-step instructions on the settings page.

= Can I disable specific actions? =

Yes. Go to WooCommerce → Felix Connector → Command Permissions and check any family you want to disable.

== Advanced: Scheduled Task (Optional) ==

For high-reliability or low-traffic setups, you can optionally add a scheduled task (a small instruction that tells your web host to run something automatically on a timer) to run the connector independently of site traffic. This replaces (or supplements) the WordPress built-in scheduler.

Copy the cron command from WooCommerce → Felix Connector → Advanced & Troubleshooting, then add it to your server:

* **SiteGround:** Site Tools → Devs → Cron Jobs → Add New. Set to run every 5 minutes.
* **cPanel:** Advanced → Cron Jobs. Set to */5 in the minute field, * in all others.
* **WP-CLI / SSH:** Add to your crontab with a 5-minute schedule.

A scheduled task and the WordPress built-in scheduler can coexist safely — they share a lock so commands are never double-executed.

== Changelog ==

= 0.2.0 =
* WP-Cron is now the default scheduling mechanism — no server cron needed
* Settings page reworked: happy path shows connection status only, server cron instructions shown only when needed
* Runner refactored for dual-context safety (WP-Cron + external CLI cron)
* Heartbeat freshness tracking via felix_last_run_at / felix_last_run_status options
* Self-healing cron schedule check on init
* DISABLE_WP_CRON detection in UI
* Server cron instructions moved to progressive-disclosure fallback

= 0.1.0 =
* Initial release
* Pairing flow with Felix dashboard
* Outbound long-poll runner (CLI, cron-launched)
* Commands: ping, get_order
* Per-command-family kill switches
* Ed25519 command signing and verification
