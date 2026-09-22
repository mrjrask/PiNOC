"""Coverage for app.js's startAutoRefresh(): dashboard, alerts, events, and
device pages previously only fetched their data once on page load, requiring
a manual browser refresh to see new telemetry, alerts, or job status.

app.js is a browser IIFE with no module system and no existing Node/JS test
harness in this repo (the Python test suite is canonical). Rather than only
grep the source, this drives the actual startAutoRefresh() logic under
Node -- real setInterval/clearInterval and a real 'visibilitychange'
listener -- with a minimal `document` stub, since that's the one genuinely
new, easy-to-get-subtly-wrong piece of behavior (pausing while hidden,
resuming, not double-scheduling).
"""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_JS = REPO_ROOT / "pinoc" / "web" / "static" / "app.js"

NODE = shutil.which("node") or shutil.which("nodejs")

DRIVER = r"""
'use strict';
const fs = require('fs');
const appJsPath = process.argv[2];
const source = fs.readFileSync(appJsPath, 'utf8');

const listeners = {};
global.document = {
  hidden: false,
  addEventListener(type, handler) {
    (listeners[type] = listeners[type] || []).push(handler);
  },
  querySelector() { return null; },
};
function fireVisibilityChange() {
  (listeners['visibilitychange'] || []).forEach(fn => fn());
}

// app.js references `window`/`navigator` in code paths this test never
// exercises (event handlers inside dashboard()/device() etc.) -- stub them
// so evaluating the whole file doesn't throw before PiNOC is even defined.
global.window = global;
global.fetch = async () => ({ ok: true, json: async () => ({}) });
global.URL = { createObjectURL: () => '', revokeObjectURL: () => {} };
global.Blob = function () {};

// app.js declares `const PiNOC=(()=>{...})();` at top level. A direct
// eval()'s let/const bindings are scoped to the eval call itself (per spec)
// and don't leak into the surrounding function scope the way `var` would,
// so rebind it as a plain global assignment instead of changing app.js.
eval(source.replace('const PiNOC=', 'global.PiNOC='));

let calls = 0;
const fn = () => { calls++; };

const results = {};

// 1. Fires on the configured interval while visible.
let stop = PiNOC.startAutoRefresh(fn, 20);
setTimeout(() => {
  results.calls_after_two_intervals = calls;

  // 2. Pausing (tab hidden) stops further calls.
  document.hidden = true;
  fireVisibilityChange();
  const callsAtPause = calls;
  setTimeout(() => {
    results.calls_stayed_same_while_hidden = (calls === callsAtPause);

    // 3. Becoming visible again resumes ticking.
    document.hidden = false;
    fireVisibilityChange();
    setTimeout(() => {
      results.resumed_after_visible_again = calls > callsAtPause;
      stop();
      const callsAfterStop = calls;
      setTimeout(() => {
        results.stop_prevents_further_calls = (calls === callsAfterStop);

        // 4. A second, independent instance in a fresh hidden tab never fires.
        let calls2 = 0;
        document.hidden = true;
        const stop2 = PiNOC.startAutoRefresh(() => { calls2++; }, 20);
        setTimeout(() => {
          results.never_fires_when_started_hidden = (calls2 === 0);
          stop2();
          console.log(JSON.stringify(results));
        }, 60);
      }, 60);
    }, 60);
  }, 60);
}, 55);
"""


@unittest.skipUnless(NODE, "node is not available in this environment")
class StartAutoRefreshTest(unittest.TestCase):
    def test_ticks_pauses_while_hidden_and_resumes(self):
        driver_path = Path(__file__).parent / "_start_auto_refresh_driver.js"
        driver_path.write_text(DRIVER, encoding="utf-8")
        self.addCleanup(driver_path.unlink)
        result = subprocess.run([NODE, str(driver_path), str(APP_JS)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertGreaterEqual(payload["calls_after_two_intervals"], 2)
        self.assertTrue(payload["calls_stayed_same_while_hidden"])
        self.assertTrue(payload["resumed_after_visible_again"])
        self.assertTrue(payload["stop_prevents_further_calls"])
        self.assertTrue(payload["never_fires_when_started_hidden"])


class TemplatesWireUpAutoRefreshTest(unittest.TestCase):
    """Each page's script block starts auto-refresh alongside its initial
    render, reusing the existing render function as-is."""

    def _script_block(self, name: str) -> str:
        return (REPO_ROOT / "pinoc" / "web" / "templates" / name).read_text(encoding="utf-8")

    def test_dashboard(self):
        self.assertIn("PiNOC.startAutoRefresh(PiNOC.dashboard)", self._script_block("dashboard.html"))

    def test_alerts(self):
        self.assertIn("PiNOC.startAutoRefresh(PiNOC.alerts)", self._script_block("alerts.html"))

    def test_events(self):
        self.assertIn("PiNOC.startAutoRefresh(PiNOC.events)", self._script_block("events.html"))

    def test_device(self):
        script = self._script_block("device.html")
        self.assertIn("PiNOC.startAutoRefresh(", script)
        self.assertIn("PiNOC.device(deviceId)", script)


if __name__ == "__main__":
    unittest.main()
