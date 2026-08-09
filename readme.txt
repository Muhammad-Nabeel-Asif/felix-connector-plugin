=== Felix Connector ===
Contributors: agentfelix
Tags: woocommerce, customer service, ai, automation, ecommerce
Requires at least: 6.0
Tested up to: 6.5
Requires PHP: 8.1
Stable tag: 0.4.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Connect your WooCommerce store to Felix (agentfelix.ai) for autonomous customer service and store operations.

== Description ==

Felix is an AI-powered customer service and executive operating partner for WooCommerce brands. This connector plugin links your store to Felix so it can look up orders, manage coupons, process refunds, and handle customer inquiries — through a secure connection that works behind any firewall.

**How it works:**

Felix delivers commands to your store over one of two transports, both sharing the same atomic execute-once pipeline so a command is never double-executed:

1. **Outbound long-poll (default, firewall-friendly):** your store initiates all communication to Felix — Felix never makes inbound requests to your store. This means the connector works behind any host firewall, captcha system, or security layer (SiteGround Anti-Bot, Cloudflare, Wordfence, and others).
2. **Direct command delivery (faster, optional):** when the store is reachable from Felix, Felix POSTs signed commands directly to `POST /wp-json/felix/v1/command`. This removes poll latency. Your store advertises this capability during polling; Felix uses it when available and falls back to long-poll otherwise.

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

* Every command is Ed25519-signed and verified before execution, on both transports
* Shared atomic command processor — poll and direct paths reserve a command ID via a single atomic INSERT, so the same command can never run twice
* A crashed reservation is never stolen: a command left mid-flight is reported as a conflict, not silently re-executed
* If a command runs but its result can't be saved, it is reported as `unconfirmed` — never a false success
* Per-command-family kill switches in plugin settings
* Refunds and money-moving actions require explicit human approval (write-authority evidence is enforced before any write handler runs)
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

By default, no — your store contacts Felix (outbound long-poll), which keeps the connector invisible to your host's firewall, captcha, or security layer. Felix can also deliver commands directly via a signed POST to your REST API when your store is reachable; your store advertises this capability and Felix falls back to long-poll if direct delivery is unavailable. Both paths verify the same Ed25519 command signature.

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

= 0.4.1 =
* Cross-language canonical JSON fixture: adds an astral-key (non-BMP) ordering case proving Node's canonical encoder now sorts object keys by UTF-8 byte value, matching PHP `ksort` byte-for-byte. No runtime behavior change for BMP keys (the realistic command-envelope case); astral keys now verify correctly where UTF-16 code-unit ordering previously diverged.

= 0.4.0 =
* New: inbound direct command delivery via POST /wp-json/felix/v1/command — Felix can now push signed commands to the store directly (no longer long-poll-only)
* New: shared atomic command processor — poll and direct transports run the identical verify → reserve → execute → persist pipeline, so a command is never double-executed across transports
* New: deterministic atomic reservation via a single PRIMARY KEY INSERT; a redelivered command returns its stored terminal result without re-executing
* New: "never steal a crashed reservation" — a command ID left in the reserved state by a crashed process is reported as a reservation conflict and is never silently re-executed
* New: terminal ledger transitions are restricted to reserved → terminal; a stale or racing writer can no longer overwrite a terminal row
* New: when a command executes but its terminal result cannot be durably persisted, the result is reported as `unconfirmed` (never a false `done`)
* New: signed capability + version advertisement on the poll request (protocol v2: storeId/generation/timestamp + plugin version + capability list)
* New: concrete write-authority enforcement — write command families require real approval evidence or a non-read graduated rule; the `connector-read` graduated rule is sufficient for reads but is denied for writes

= 0.3.1 =
* Fix: guest order matching in search_orders now uses the 'search' parameter with an exact email filter

= 0.3.0 =
* New: sync_orders + sync_products handlers for data-plane backfill

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
