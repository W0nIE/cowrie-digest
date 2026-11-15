# Channel setup guide

`cowrie-digest` supports two delivery channels. Pick one.

---

## Option A — ntfy.sh (recommended, 2 minutes)

[ntfy](https://ntfy.sh) is a free push-notification service. No account needed.

1. **Pick a topic name** — this is your "channel URL". Make it long and random,
   because anyone who knows the topic can read it:
   ```
   cowrie-alerts-x7k9qm2vdp4w
   ```
2. **Set it in config.env:**
   ```
   CHANNEL=ntfy
   NTFY_TOPIC=cowrie-alerts-x7k9qm2vdp4w
   ```
3. **Subscribe on your phone:**
   - Install *ntfy* (Android: Google Play / F-Droid, iOS: App Store)
   - Add subscription → topic `cowrie-alerts-x7k9qm2vdp4w` on server `https://ntfy.sh`
   - Or on desktop: `https://ntfy.sh/cowrie-alerts-x7k9qm2vdp4w`
4. **Test:**
   ```bash
   sudo /opt/cowrie/ops/01-digest/digest.py --digest
   ```
   You should get a push notification within seconds.

Self-hosting ntfy? Set `NTFY_SERVER=https://your-ntfy-host` — done.

---

## Option B — Telegram bot

1. **Create the bot:** talk to [@BotFather](https://t.me/BotFather) →
   `/newbot` → follow prompts → copy the token (`123456:ABC-DEF...`).
2. **Get your chat_id:** start a chat with your new bot, send any message,
   then talk to [@userinfobot](https://t.me/userinfobot) — it shows your numeric id.
   (For a group: add the bot to the group, send a message there, then open
   `https://api.telegram.org/bot<TOKEN>/getUpdates` and find `"chat":{"id":-100...}`.)
3. **Set in config.env:**
   ```
   CHANNEL=telegram
   TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
   TELEGRAM_CHAT_ID=123456789
   ```
4. **Test:**
   ```bash
   sudo /opt/cowrie/ops/01-digest/digest.py --digest
   ```

---

## Verifying cron works

After install, cron runs the digest at 09:00 and alerts every 5 minutes.
Check it manually anytime:

```bash
sudo /opt/cowrie/ops/01-digest/digest.py --print   # preview, sends nothing
cat /opt/cowrie/ops/01-digest/log/digest.log        # cron output history
```
