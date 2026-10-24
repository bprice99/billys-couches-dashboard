/**
 * Billy's Couches Dashboard - Google Sheets API
 *
 * SETUP (one time):
 * 1. Open the "Customer Database Trackers" Google Sheet (the one with the Sales Log tab).
 * 2. Extensions > Apps Script. Create a NEW file (+ > Script), name it "Dashboard", paste this whole file. Save.
 * 3. Change SECRET below to any long random phrase. You'll paste the same phrase into Railway as SHEETS_KEY.
 * 4. Run the "setup" function once (select it at the top, click Run, approve permissions).
 *    This creates the "Purchases" and "Expenses" tabs if they don't exist.
 * 5. Deploy > New deployment > Web app. Execute as: Me. Who has access: Anyone. Deploy, copy the URL.
 *    Paste that URL into Railway as SHEETS_API_URL.
 *
 * The dashboard only reads/writes through this script, and only with the SECRET.
 */

var SECRET = 'CHANGE-ME-to-a-long-random-phrase';

// Tab names. Change these if yours are named differently.
var TABS = {
  sales: 'Sales Log',
  purchases: 'Purchases',
  expenses: 'Expenses'
};

var PURCHASE_HEADERS = ['Date', 'Source', 'Item', 'Units', 'Cost', 'Load ID', 'Notes'];
var EXPENSE_HEADERS = ['Date', 'Category', 'Amount', 'Vendor', 'Notes'];

function setup() {
  ensureTab(TABS.purchases, PURCHASE_HEADERS);
  ensureTab(TABS.expenses, EXPENSE_HEADERS);
}

function ensureTab(name, headers) {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sh = ss.getSheetByName(name);
  if (!sh) {
    sh = ss.insertSheet(name);
    sh.appendRow(headers);
    sh.getRange(1, 1, 1, headers.length).setFontWeight('bold');
    sh.setFrozenRows(1);
  }
  return sh;
}

function readTab(name) {
  var sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(name);
  if (!sh) return { headers: [], rows: [] };
  var vals = sh.getDataRange().getValues();
  if (!vals.length) return { headers: [], rows: [] };
  var tz = Session.getScriptTimeZone();
  var rows = vals.slice(1)
    .filter(function (r) { return r.some(function (c) { return c !== '' && c !== null; }); })
    .map(function (r) {
      return r.map(function (c) {
        return (c instanceof Date) ? Utilities.formatDate(c, tz, 'yyyy-MM-dd') : c;
      });
    });
  return { headers: vals[0].map(String), rows: rows };
}

function doGet(e) {
  var p = (e && e.parameter) || {};
  if (p.key !== SECRET) return out({ error: 'unauthorized' });
  return out({
    ok: true,
    sales: readTab(TABS.sales),
    purchases: readTab(TABS.purchases),
    expenses: readTab(TABS.expenses),
    at: new Date().toISOString()
  });
}

function doPost(e) {
  var body = {};
  try { body = JSON.parse(e.postData.contents); } catch (err) { return out({ error: 'bad json' }); }
  if (body.key !== SECRET) return out({ error: 'unauthorized' });

  var d = body.data || {};
  var date = d.date ? new Date(d.date + 'T12:00:00') : new Date();

  if (body.action === 'addPurchase') {
    var cost = Number(d.cost);
    if (!(cost >= 0)) return out({ error: 'Cost is required' });
    ensureTab(TABS.purchases, PURCHASE_HEADERS).appendRow([
      date, d.source || '', d.item || '', Number(d.units || 1), cost, d.loadId || '', d.notes || ''
    ]);
    return out({ ok: true });
  }

  if (body.action === 'addExpense') {
    var amt = Number(d.amount);
    if (!(amt > 0)) return out({ error: 'Amount is required' });
    ensureTab(TABS.expenses, EXPENSE_HEADERS).appendRow([
      date, d.category || 'Other', amt, d.vendor || '', d.notes || ''
    ]);
    return out({ ok: true });
  }

  return out({ error: 'unknown action' });
}

function out(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}
