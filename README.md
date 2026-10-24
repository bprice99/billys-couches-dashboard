# Billy's Couches Dashboard

Tabs: Sales Tracker, Showings, Meta Ads, B-Stock Loads, Couch List.

## Railway variables
- APP_PASSWORD - login password
- SHEETS_API_URL - Apps Script web app URL (reads Sales Log + Billy's Couches calendar)
- SHEETS_KEY - the SECRET in apps-script.gs
- UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN - where purchases, expenses and B-Stock loads are saved (copy from the order app)

## Where data comes from
- Sales: Sales Log (filled by the order apps). Jan-Sep 2026 from history.json (Ivy Flip export).
- Purchases, expenses, B-Stock loads: entered in the dashboard, saved in Upstash.
- Showings: Billy's Couches Google Calendar. "(Canceled)" = canceled, green = bought, "(No show)" or gray = no-show.
- Couch List: billyscouches.com/currentinventory.
