# Billy's Couches Dashboard - setup (about 15 minutes)

## 1. Google Sheet script
1. Open the **Customer Database Trackers** sheet (the one with the Sales Log tab).
2. Extensions > Apps Script > + > Script. Name it `Dashboard`, paste `apps-script.gs`.
3. Change `SECRET` to a long random phrase. Save.
4. Pick `setup` at the top and click Run (approve permissions). This adds **Purchases** and **Expenses** tabs.
5. Deploy > New deployment > Web app. Execute as **Me**, access **Anyone**. Copy the URL.

## 2. GitHub + Railway
1. New private GitHub repo `billys-couches-dashboard`. Upload: `server.js`, `index.html`, `login.html`, `package.json`.
2. Railway > New Project > Deploy from GitHub repo > pick it.
3. Variables:
   - `APP_PASSWORD` = your password
   - `SHEETS_API_URL` = the Web app URL from step 1
   - `SHEETS_KEY` = the SECRET phrase from step 1
4. Settings > Networking > Generate Domain. Open it and log in.

## 3. Load your history
- **Expenses:** Ivy Flip > Sales Tracker > Download. Paste the expense rows into the Expenses tab (Date, Category, Amount, Vendor, Notes).
- **Purchases:** one row per B-Stock load (Date arrived, Bstock, load name, units, landed cost, Load ID) and one row per used couch you bought.

Sales come straight from the Sales Log your order apps already fill in. From now on, log purchases and expenses with the + buttons.
