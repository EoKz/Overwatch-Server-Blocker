# OW Server Blocker

Simple Windows app for blocking selected Overwatch 2 server regions only for `Overwatch.exe`.

![App screenshot](assets/app-screenshot.png)

## How It Works

OW Server Blocker creates one outbound Windows Firewall rule named `OWServerBlocker - Overwatch.exe`.

The rule is scoped to the selected `Overwatch.exe` path and blocks only the server regions or expanded server targets you select in the app. Changing the selection replaces the previous rule, so old blocks are not duplicated or left behind.

The app remembers your selected executable path and checked targets in a small local settings file. Latency values are simple ICMP probes and may show timeout even when a game server is reachable.

## How To Use

1. Download and extract the release zip.
2. Run `owsvblocker.exe` as administrator.
3. Click `Select Overwatch.exe` and choose your game executable.
4. Select the server regions you want to block, or expand a region to choose specific targets.
5. Click `Apply selected block(s)`.

To remove every block created by the app, open it as administrator and click `Unblock all`.
