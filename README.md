# Felix Connector

WordPress / WooCommerce plugin that connects a store to [Felix](https://agentfelix.ai). Felix sends **typed, signed commands**. This plugin executes them locally. There is no generic PHP executor and no raw SQL.

Current version: **0.4.3** (`FELIX_CONNECTOR_VERSION`).

Merchant install zip: [GitHub Releases](https://github.com/Orchestra-AI-Video/felix-connector-plugin/releases). Until a `v0.4.3` GitHub Release exists, Latest on that page may still be an older zip even though `main` is 0.4.3.

This GitHub `README.md` is for operators and developers. The WordPress.org-style file for the plugin zip is [`readme.txt`](readme.txt).

## What it does

- Looks up orders, products, customers, coupons, and subscriptions (HPOS and classic post storage)
- Updates order status and shipping address
- Creates comp / free orders
- Creates, updates, and deactivates coupons
- Processes refunds (write authority required)
- Syncs orders, products, and coupons for Felix’s data mirror
- Manages WooCommerce webhooks Felix registers

Kill switches in **WooCommerce → Felix Connector** can disable any command family on that store.

## How commands are delivered

Both paths use the **same** pipeline: verify Ed25519 signature → check store / generation / TTL → check write authority → **atomic ledger insert** (exactly once) → handler → persist terminal result.

| Path | When | Direction |
| --- | --- | --- |
| Long-poll (default) | Always available | Store calls Felix (`/connector/poll`, then `/connector/result`) |
| Direct REST | Store reachable from Felix | Felix `POST /wp-json/felix/v1/command` |

Direct delivery is advertised on poll (`directCommandV1`). If it fails, Felix falls back to poll. The same command id cannot run twice across the two paths.

Unpaired `POST /wp-json/felix/v1/command` returns a generic **HTTP 404** (no `not_paired` body). GET is not a route.

## Production requirement: poll every 60 seconds

Felix commands expire after **120 seconds**. This plugin’s WP-Cron event is **every 60 seconds** (`felix_minute`).

**Required in production:** a host scheduler that fires at least once per minute.

- Preferred: system cron / host panel hitting `wp-cron.php` every 1 minute
- Alternative: PHP CLI `runner.php` every 1 minute (as the web user; HTTP to this file returns 403)
- **Not enough:** page-view WP-Cron alone
- **Unsafe:** a 5-minute host cron (300s > 120s TTL)

Copy the exact command from **WooCommerce → Felix Connector**. Do not point cron at `runner.php` unless that file is on disk (v0.4.0 zips omitted it).

WP-Cron and `runner.php` share a lock; they can run together without double-executing.

If the store is stuck on Connecting…, click **Check in now**.

## Install (merchant)

1. Download `felix-connector.zip` from [Releases](https://github.com/Orchestra-AI-Video/felix-connector-plugin/releases) (not a random Actions artifact).
2. WordPress → Plugins → Add New → Upload.
3. Activate. Open **WooCommerce → Felix Connector**.
4. Enter the pairing code from the Felix dashboard (format `XXXX-XXXX`; hyphen is cosmetic).
5. Add the 1-minute scheduled task from the settings page.

Requires **WordPress 6.0+**, **PHP 8.1+**, **WooCommerce**, and the **sodium** PHP extension (Ed25519).

## `wp-config.php`

Pairing posts to the Felix API origin. Missing config **fails closed** — it will not silently pair against production from local or staging.

```php
// Required unless FELIX_ENVIRONMENT is exactly "production"
define( 'FELIX_API_BASE', 'https://api.agentfelix.ai' );
```

| Setting | Effect |
| --- | --- |
| `FELIX_API_BASE` | Always wins. Use this in production, staging, and local. |
| `FELIX_ENVIRONMENT` = `production` | If `FELIX_API_BASE` is unset, defaults to `https://api.agentfelix.ai` |
| Anything else, or unset | Empty origin → pairing is refused |

Optional CLI: `WP_LOAD_PATH` if `runner.php` cannot find `wp-load.php` by walking up from `wp-content/plugins`.

## Layout

```
felix-connector.php          Plugin bootstrap, 60s cron, check-in
runner.php                   CLI poll loop (must ship in the zip)
uninstall.php                Options + ledger table cleanup
includes/
  class-felix-crypto.php             Ed25519 + local secretbox
  class-felix-pairing.php            Pair / unpair
  class-felix-settings.php           Admin UI, API base, cron copy
  class-felix-runner.php             Poll + result POST
  class-felix-rest.php               Direct command endpoint
  class-felix-command-processor.php  Shared verify → reserve → execute
  class-felix-command-ledger.php     wp_felix_connector_commands
  class-felix-command-handlers.php   Typed handlers (deny by default)
scripts/                     Zip build, zip assert, (optional) GitHub Release
tests/                       Offline behavioral tests (not in the merchant zip)
```

## Commands

Unknown types are rejected (`unknown_type`). Invalid money (more than 2 decimal places) or quantity is `validation_error` **before** WooCommerce is mutated. Engine errors become a terminal `failed` envelope (`Throwable`), not a PHP fatal.

| Family | Commands |
| --- | --- |
| system | `ping` |
| order_read | `get_order`, `search_orders` (`billing_email`), `list_orders` |
| product_read | `get_product`, `list_products` |
| customer_read | `list_customers` |
| coupon_read | `get_coupon`, `list_coupons` |
| subscription_read | `get_subscription`, `list_subscriptions`, `list_subscriptions_for_customer` |
| order_write | `update_order_status`, `update_order_shipping_address` |
| order_create | `create_order` |
| coupon_write | `create_coupon`, `update_coupon`, `deactivate_coupon` |
| subscription_write | `update_subscription_status`, `renew_subscription` |
| refund | `refund.create` |
| customer_write | `delete_customer` |
| webhook_management | `register_webhooks`, `verify_webhooks`, `remove_webhooks` |
| sync | `sync_orders`, `sync_products`, `sync_coupons` |

Writes need approval (or a non-read graduated rule). The `connector-read` rule is enough for reads only.

Webhook `deliveryUrl` must be `https` and must not target localhost or private / reserved IPs.

## Security (short)

- Plugin Ed25519 secret never leaves the store
- Felix signs every command; bad / unknown key / wrong generation / expired TTL → reject, no handler
- Replay: command-id ledger + nonce
- Crashed reservation is not stolen; stale reserve becomes `unconfirmed`
- If the handler ran but the terminal row cannot be saved → `unconfirmed`, never a false `done`
- Re-pair bumps generation; old-generation envelopes are rejected

## Develop

PHP 8.1+ with `sodium` and `zip`.

```bash
php tests/run.php
bash scripts/build-zip.sh
php scripts/assert-zip-contents.php dist/felix-connector.zip
```

The zip contains plugin PHP + `readme.txt` + `runner.php`. It does **not** contain `tests/`.

CI (`.github/workflows/ci.yml`) runs those three steps on pull requests and on `main`.

## License

GPL-2.0-or-later. See the plugin header in `felix-connector.php`.
