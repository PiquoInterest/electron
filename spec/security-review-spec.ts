import { app, BrowserWindow, dialog, ipcMain, session, WebContents } from 'electron/main';

import { expect } from 'chai';

import * as crypto from 'node:crypto';
import { once } from 'node:events';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { setTimeout } from 'node:timers/promises';

import { defer, listen, waitUntil } from './lib/spec-helpers';
import { closeAllWindows } from './lib/window-helpers';

// ---------------------------------------------------------------------------
// READ THIS BEFORE EDITING — THE POLARITY OF THIS FILE IS INVERTED.
//
// Every test in this file asserts the SECURE behaviour: the behaviour that
// *should* hold once the corresponding finding in SECURITY-REVIEW.md is fixed.
// These are NOT characterization tests. They do not describe what Electron does
// today — they describe what it ought to do. Each one is therefore
// EXPECTED TO FAIL on the current tree and EXPECTED TO PASS once the finding is
// fixed. That is the opposite of how the rest of spec/ is written.
//
// Because of that, every test here is registered with `it.skip(...)` so CI stays
// green. Remove the `.skip` on an individual test to reproduce the finding it
// documents. When a finding is fixed, remove the `.skip` permanently and the
// test becomes an ordinary regression test.
//
// Each `describe` block carries: the finding name and its ID in
// SECURITY-REVIEW.md, the file:line of the defect, and one sentence on what the
// test proves.
//
// ---------------------------------------------------------------------------
// FINDINGS THAT COULD NOT BE GIVEN A RUNTIME TEST, AND WHY
//
// * A1 — Fork-PR code execution on self-hosted runners (CRITICAL). A property of
//   the GitHub Actions configuration and a repository setting that is not stored
//   in-tree. There is no app-runtime surface at all; it is not observable from
//   inside a running Electron process by any means.
//
// * B1 — the *mojo* half of preload code-cache poisoning. `SetPreloadCodeCache`
//   is a renderer→browser mojo method with no JavaScript surface, so the exact
//   attacker call cannot be made from a spec. What IS testable is the on-disk
//   consequence of the missing provenance check, which is what the B1 block
//   below does; see the comment there for exactly how far that proof reaches.
//
// * B3 — asar integrity validation skipped in macOS helper processes. Requires a
//   signed, notarized .app bundle with `EnableEmbeddedAsarIntegrityValidation`
//   fused on and a separately tampered archive inside it. The spec runner is an
//   unpackaged development build with no embedded asar and no code signature, so
//   the code path under test is inert here.
//
// * B5 — site-isolation drag-target check patched to `return true`. Needs a
//   synthesized cross-process drag-and-drop gesture between two OOPIFs; Electron
//   exposes no API to originate a real drag from the browser process, and
//   `webContents.startDrag` does not exercise the patched check.
//
// * C3 — WebUI factory matches host without checking scheme. Reaching it needs a
//   navigation to a *single-label* host (e.g. `http://accessibility/`) that
//   actually resolves, i.e. control of DNS or a HOSTS entry on the test machine.
//   The spec runner's `--host-resolver-rules` could be extended to fake this,
//   but that is a change to spec/index.js affecting every other suite, so it is
//   deliberately not done here.
//
// * C7, C8, C9 — the Bluetooth allowlist stubs, the Bluetooth serial grant
//   match-all, and serial revocation leaving open ports live. All require real
//   Bluetooth/serial hardware attached to the test machine. See the B4 block
//   below for the same hardware constraint stated concretely.
//
// * C12 — `app.isPackaged` spoofable by renaming a signed executable. Requires a
//   packaged build to rename; the spec runner is not packaged.
//
// * C14 — V8 snapshot checksum vs the browser-snapshot fuse. Requires a build
//   with the fuse flipped, i.e. a different binary, not a different test.
//
// * C17, C21 — the DevTools context-menu UAF during a blocking macOS menu, and
//   Crashpad client PID spoofing on Windows. Both need a native, blocking UI or
//   IPC interaction that cannot be driven from a headless spec run.
// ---------------------------------------------------------------------------

describe('security review findings', () => {
  const fixtures = path.resolve(__dirname, 'fixtures');

  describe('B2 — renderer-controlled session partition name', () => {
    // Finding:  SECURITY-REVIEW.md B2, "Renderer-controlled session partition
    //           name" (HIGH).
    // Defect:   shell/browser/api/electron_api_session.cc:1760 accepts any
    //           `persist:` name with no character validation, and the name
    //           becomes an on-disk path via MakePartitionName -> base::EscapePath
    //           (shell/browser/electron_browser_context.cc:238-240, :381-385),
    //           which leaves `.` and `/` unescaped. The renderer reaches it
    //           through lib/browser/guest-view-manager.ts:45, which passes the
    //           `<webview partition="...">` attribute straight through;
    //           `partition` is absent from the inheritedWebPreferences forcing
    //           map at lib/browser/guest-view-manager.ts:54-61.
    // Proves:   (a) a `persist:` name containing `..` escapes the app's
    //           Partitions directory, and (b) attacker-authored markup in a
    //           `webviewTag: true` window can place a guest into a session
    //           partition the embedder never authorised.

    afterEach(closeAllWindows);

    it.skip('rejects a persist: partition name that escapes the sessions directory', () => {
      // EXPECTED TO FAIL until B2 (renderer-controlled session partition name) is fixed; remove .skip to reproduce
      //
      // Only a single `..` is used. The traversal variant in the finding
      // (`persist:../../../../evil`) writes a cookies DB, Local Storage,
      // IndexedDB and prefs outside the app's data directory entirely, which is
      // not something a test should do to the machine it runs on. One level up
      // lands in `<sessionData>/` instead of `<sessionData>/Partitions/`, which
      // is already outside the containment boundary and so proves the same
      // thing without scribbling outside the app. MakePartitionName lowercases
      // the name, so the name is kept lowercase to stay predictable.
      const partitionsRoot = path.resolve(app.getPath('sessionData'), 'Partitions');
      const name = `../electron-security-review-${crypto.randomUUID().toLowerCase()}`;

      let ses: Electron.Session | undefined;
      try {
        ses = session.fromPartition(`persist:${name}`);
      } catch {
        // Throwing on a traversing partition name is an acceptable secure
        // outcome — the point is that the traversal must not silently succeed.
        return;
      }

      // A `persist:` partition is not in-memory, so it must have a storage path.
      expect(ses.storagePath).to.be.a('string');
      const resolved = path.resolve(ses.storagePath!);
      const relative = path.relative(partitionsRoot, resolved);
      const escapes = relative === '' || relative.startsWith('..') || path.isAbsolute(relative);
      expect(escapes).to.equal(
        false,
        `partition storage path escaped ${partitionsRoot}: ${resolved} (relative: ${relative})`
      );
    });

    it.skip('does not place a <webview> guest in a partition named only by the renderer', async () => {
      // EXPECTED TO FAIL until B2 (renderer-controlled session partition name) is fixed; remove .skip to reproduce
      //
      // The impact the finding describes is not the traversal but this: page
      // content picks the *app's own* trusted partition by name and gets its
      // cookie jar, permission handlers, custom protocol handlers, proxy config
      // and setCertificateVerifyProc — and can then script a document loaded in
      // it, because `executeJavaScript` is on the webview async-method allowlist
      // (lib/common/web-view-methods.ts:68).
      const trustedPartition = 'persist:security-review-trusted';
      const trustedSession = session.fromPartition(trustedPartition);

      const w = new BrowserWindow({ show: false, webPreferences: { webviewTag: true } });

      // The embedder deliberately installs a no-op `will-attach-webview` handler:
      // this models an app that does not sanitise, which is the default posture.
      // (Today the `webPreferences.partition` this handler is handed is exactly
      // the attacker's string; that current value is intentionally NOT asserted
      // here, because asserting it would invert polarity and break once B2 is
      // fixed. The assertion below is on the outcome instead.)
      const attachedPartitions: Array<string | undefined> = [];
      w.webContents.on('will-attach-webview', (_event, webPreferences) => {
        attachedPartitions.push(webPreferences.partition);
      });

      const guestCreated = once(app, 'web-contents-created') as Promise<[any, WebContents]>;
      const markup = `<webview partition="${trustedPartition}" src="about:blank"></webview>`;
      await w.loadURL(`data:text/html,${encodeURIComponent(markup)}`);
      const [, guest] = await guestCreated;

      expect(attachedPartitions).to.have.lengthOf(1);
      expect(guest.getType()).to.equal('webview');
      expect(guest.session).to.not.equal(
        trustedSession,
        'a renderer-authored partition attribute must not place the guest in the trusted session of the app'
      );
    });
  });

  describe('B4 — serial.forget() with an unknown port token', () => {
    // Finding:  SECURITY-REVIEW.md B4, "`serial.forget()` dereferences an end
    //           iterator" (HIGH).
    // Defect:   shell/browser/serial/serial_chooser_context.cc:135-158 — the
    //           `port_info_.find(token)` guard closes at :142, but the same
    //           iterator is dereferenced again at :158 (`details.Set("port",
    //           it->second)`) when building the `serial-port-revoked` payload.
    //           The gin converter follows the pointer immediately
    //           (shell/common/gin_converters/serial_port_info_converter.h:21,
    //           `port->token.ToString()`), so an end() iterator is read as if it
    //           were a SerialPortInfoPtr.
    // Proves:   the browser process survives a revocation for a token that is no
    //           longer in `port_info_`, and that `serial-port-revoked` never
    //           carries a garbage `port` value.
    //
    // HONESTY — THIS TEST CANNOT FAIL ON ANY MACHINE WITHOUT A SERIAL DEVICE.
    // The two triggers the finding identifies are:
    //   (a) a page holds a `SerialPort`, the user PHYSICALLY UNPLUGS the device
    //       (OnPortRemoved() erases port_info_ at serial_chooser_context.cc:246),
    //       the JS object survives, and `port.forget()` then arrives with a stale
    //       token; and
    //   (b) a compromised renderer calling `blink.mojom.SerialService.ForgetPort()`
    //       with an arbitrary 128-bit value — no JavaScript surface.
    // Neither is reachable from a spec run: (a) needs hardware AND a human to
    // unplug it mid-test, (b) needs a renderer compromise. Note in particular
    // that calling `forget()` twice does NOT reach the bug: only OnPortRemoved()
    // erases from `port_info_`, so the second forget still finds its entry.
    //
    // What is written below is therefore the observable PROXY the finding allows:
    // every `serial-port-revoked` the session emits must carry a well-formed port
    // object. On a machine with a real serial port attached it exercises the
    // grant/revoke path for real; with no port attached it self-skips. It is a
    // guard against the corrupted-payload symptom, not a proof of the defect.
    // Keeping it `.skip`ped is consistent with the rest of the file and avoids a
    // hardware-dependent test in CI.

    let w: BrowserWindow;

    before(async () => {
      w = new BrowserWindow({ show: false });
      await w.loadFile(path.join(fixtures, 'pages', 'blank.html'));
    });

    after(closeAllWindows);

    afterEach(() => {
      session.defaultSession.removeAllListeners('select-serial-port');
      session.defaultSession.removeAllListeners('serial-port-revoked');
      session.defaultSession.setPermissionCheckHandler(null);
      session.defaultSession.setDevicePermissionHandler(null);
    });

    it.skip('only ever emits serial-port-revoked with a well-formed port', async function () {
      // EXPECTED TO FAIL until B4 (serial.forget() end-iterator dereference) is fixed; remove .skip to reproduce
      // — but see the HONESTY note above: without an attached serial device that
      // is removed mid-test, this cannot reach the defective code path and will
      // pass vacuously.
      let havePorts = false;
      w.webContents.session.on('select-serial-port', (_event, portList, _webContents, callback) => {
        if (portList.length > 0) {
          havePorts = true;
          callback(portList[0].portId);
        } else {
          callback('');
        }
      });
      session.defaultSession.setDevicePermissionHandler(() => true);

      const revocations: any[] = [];
      w.webContents.session.on('serial-port-revoked', (_event, details) => {
        revocations.push(details);
      });

      await w.webContents.executeJavaScript(
        'navigator.serial.requestPort().then(port => port.toString()).catch(err => err.toString());',
        true
      );

      if (!havePorts) {
        // No serial hardware on this machine — nothing to revoke.
        return this.skip();
      }

      const grantedPorts = await w.webContents.executeJavaScript('navigator.serial.getPorts()');
      if (grantedPorts.length === 0) return this.skip();

      await w.webContents.executeJavaScript(`
        navigator.serial.getPorts().then(async (ports) => {
          await ports[0].forget();
          // A second forget() on the same JS object: harmless today because only
          // device removal erases port_info_, but it is the closest a spec can
          // get to the stale-token shape without unplugging the device.
          try { await ports[0].forget(); } catch {}
          return true;
        })
      `);

      await waitUntil(() => revocations.length > 0);

      for (const details of revocations) {
        expect(details).to.be.an('object');
        expect(details.port, 'serial-port-revoked emitted without a port').to.be.an('object');
        // If `it` were an end() iterator, `port->token.ToString()` would have
        // read past the tree sentinel and portId would be garbage or absent.
        expect(details.port.portId).to.be.a('string');
        expect(details.port.portId).to.not.equal('');
      }
    });
  });

  describe('C2 — legacy getUserMedia desktop capture bypasses setDisplayMediaRequestHandler', () => {
    // Finding:  SECURITY-REVIEW.md C2, "Legacy `getUserMedia` desktop capture
    //           bypasses the display-media handler" (MEDIUM, arguably HIGH).
    // Defect:   shell/browser/web_contents_permission_helper.cc:49-58, :105-119
    //           and :154-158 route GUM_DESKTOP_VIDEO_CAPTURE /
    //           GUM_DESKTOP_AUDIO_CAPTURE to HandleUserMediaRequest() *before*
    //           the DISPLAY_VIDEO_CAPTURE branch that consults
    //           setDisplayMediaRequestHandler. With no source id, GetScreenId()
    //           synthesizes {TYPE_SCREEN, -1} — the entire desktop.
    // Proves:   a setDisplayMediaRequestHandler that denies is honoured on the
    //           legacy constraint path too, so an app that implemented the
    //           handler really has gated screen capture.
    //
    // OPPOSITE POLARITY, SAME BEHAVIOUR: spec/api-media-handler-spec.ts:397-414,
    // 'is not called when calling legacy getUserMedia with desktop capture
    // constraint', asserts the CURRENT behaviour — the handler is bypassed and
    // the page DOES receive a stream (`expect(ok).to.be.true()`). That test
    // passes today and this one fails. Fixing C2 flips both; whoever lands the
    // fix must update that test in the same change.

    afterEach(closeAllWindows);

    // An http server is used rather than about:blank so the page runs on a
    // trustworthy origin, matching spec/api-media-handler-spec.ts.
    let server: http.Server;
    let serverUrl: string;

    before(async () => {
      server = http.createServer((_req, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.end('');
      });
      serverUrl = (await listen(server)).url;
    });

    after(() => {
      server.close();
    });

    it.skip('denies a legacy desktop-capture getUserMedia when the display media handler denies', async () => {
      // EXPECTED TO FAIL until C2 (legacy getUserMedia bypasses the display
      // media handler) is fixed; remove .skip to reproduce
      const ses = session.fromPartition('' + Math.random());
      let requestHandlerCalled = false;
      ses.setDisplayMediaRequestHandler(() => {
        requestHandlerCalled = true;
        // Throwing from the handler is how the existing media-handler specs
        // express "this must never be reached / this denies".
        throw new Error('denied by security-review-spec');
      });

      const w = new BrowserWindow({ show: false, webPreferences: { session: ses } });
      await w.loadURL(serverUrl);

      const { ok, message } = await w.webContents.executeJavaScript(`
        new Promise((resolve) => navigator.getUserMedia({
          video: {
            mandatory: {
              chromeMediaSource: 'desktop'
            }
          },
        },
        x => resolve({ ok: x instanceof MediaStream, message: null }),
        e => resolve({ ok: false, message: e.message })))
      `);

      expect(requestHandlerCalled).to.equal(
        true,
        'setDisplayMediaRequestHandler must be consulted for the legacy desktop-capture constraint'
      );
      expect(ok).to.equal(false, `page must not receive a desktop stream (getUserMedia said: ${message})`);
    });
  });

  describe('B1 — preload V8 code cache accepts a blob of unverified provenance', () => {
    // Finding:  SECURITY-REVIEW.md B1, "Preload V8 code-cache poisoning via a
    //           renderer-supplied source hash" (HIGH).
    // Defect:   shell/browser/electron_web_contents_utility_handler_impl.cc:97-109
    //           accepts BOTH the code-cache blob and its claimed source hash from
    //           the renderer; IsPreloadIdServedToFrame validates only the cache
    //           *key*, never the blob's provenance.
    //           shell/browser/preload_code_cache.cc:103 then serves that blob to
    //           any renderer whose real preload source hashes to the stored
    //           value. There is no V8 backstop: SerializedCodeData::SourceHash is
    //           a source-*length* field plus two bits, with no content hash — as
    //           Electron's own mojom comment says at
    //           shell/common/web_contents_utility.mojom:23-30, "V8's own
    //           CachedData source check is length-only, so it cannot reject a
    //           same-length source change".
    // Proves:   end to end, that a cache entry whose stored hash matches the
    //           victim preload but whose blob was compiled from *different
    //           source of the same length* is not executed.
    //
    // HOW FAR THIS PROOF REACHES. The mojo method itself has no JavaScript
    // surface, so the attacker's exact call cannot be made from a spec. What is
    // done instead is to write the resulting entry to the on-disk tier directly:
    // `<userData>/Code Cache/electron-preload/<sha256(id)>.cache`, whose format is
    // 'EPC1' + sha256(source) + blob (preload_code_cache.cc:29-31, :50-59,
    // :61-74). A renderer that calls Set() with a forged pair produces exactly
    // these bytes (Set() at :121-129 concatenates magic + the renderer's hash +
    // the renderer's blob), so the on-disk plant is byte-identical to the
    // outcome of the mojo attack and reaches the same Get() path. What it does
    // not cover is the *reachability* half of B1 — that a cross-origin OOPIF
    // which was never served the preload can perform the write, because the
    // interface is registered outside the ElectronApiIPC gate
    // (shell/browser/electron_browser_client.cc:1633-1650).
    //
    // The in-memory tier (preload_code_cache.cc:43-48) shadows disk for the
    // lifetime of the browser process and memoizes misses, so a preload path
    // that has already been loaded in this process will never re-read disk.
    // Every test below therefore uses a fresh temp preload path and plants the
    // file BEFORE that path is ever loaded.

    const cacheDir = path.join(app.getPath('userData'), 'Code Cache', 'electron-preload');
    const MAGIC = Buffer.from('EPC1', 'ascii');
    const SHA256_LENGTH = 32;
    const HEADER_LENGTH = MAGIC.length + SHA256_LENGTH;
    const MARKER_CHANNEL = 'security-review-preload-marker';

    // Both markers are exactly five characters so the two preload sources are
    // byte-for-byte the same LENGTH while differing in content. That is the whole
    // point: V8's CachedData source check is length-only, so a blob compiled from
    // one is accepted for the other.
    const preloadSource = (marker: string) =>
      `require('electron').ipcRenderer.send('${MARKER_CHANNEL}', '${marker}');\n`;

    const cacheFileFor = (preloadPath: string) => {
      // preload_code_cache.cc:85-87 (id) and :50-59 (filename).
      const id = `preload-${preloadPath}`;
      const digest = crypto.createHash('sha256').update(id).digest('hex').toUpperCase();
      return path.join(cacheDir, `${digest}.cache`);
    };

    const tempFiles: string[] = [];
    const makePreload = (marker: string) => {
      const preloadPath = path.join(os.tmpdir(), `security-review-preload-${crypto.randomUUID()}.js`);
      fs.writeFileSync(preloadPath, preloadSource(marker));
      tempFiles.push(preloadPath, cacheFileFor(preloadPath));
      return preloadPath;
    };

    const waitFor = async (predicate: () => boolean, what: string, timeoutMs = 10000) => {
      const start = Date.now();
      while (Date.now() - start < timeoutMs) {
        if (predicate()) return;
        await setTimeout(50);
      }
      throw new Error(`timed out waiting for ${what}`);
    };

    // Windows keeps a handle on a file that was just written from the thread
    // pool; retry rather than fail the cleanup. Mirrors the helper in
    // spec/api-browser-window-spec.ts's 'preload code cache' suite.
    const removeFile = async (filePath: string) => {
      await waitFor(() => {
        try {
          fs.rmSync(filePath, { force: true });
          return true;
        } catch (error: any) {
          if (error.code === 'ENOENT') return true;
          if (error.code === 'EPERM' || error.code === 'EBUSY') return false;
          throw error;
        }
      }, `remove ${filePath}`);
    };

    afterEach(async () => {
      await closeAllWindows();
      for (const filePath of tempFiles) await removeFile(filePath);
      tempFiles.length = 0;
    });

    // The code cache is only produced and consumed for sandboxed preloads.
    const makeWindow = (preload: string) =>
      new BrowserWindow({
        show: false,
        webPreferences: { sandbox: true, contextIsolation: true, preload }
      });

    const runPreload = async (preload: string) => {
      const w = makeWindow(preload);
      const ran = once(ipcMain, MARKER_CHANNEL);
      await w.loadFile(path.join(fixtures, 'api', 'blank.html'));
      const [, marker] = await ran;
      return { w, marker };
    };

    it.skip('does not execute a cached blob compiled from different source of the same length', async () => {
      // EXPECTED TO FAIL until B1 (preload code cache accepts a
      // renderer-supplied blob) is fixed; remove .skip to reproduce
      const donorPath = makePreload('DONOR');
      const victimPath = makePreload('VICTM');
      expect(preloadSource('DONOR')).to.have.lengthOf(
        preloadSource('VICTM').length,
        'the two preload sources must be the same length for this to model the attack'
      );

      // 1. Run the donor once so V8 produces a GENUINE, checksum-valid code cache
      //    blob for the donor's bytecode. Using a real blob is what makes this a
      //    proof rather than a corruption test: V8's own payload checksum cannot
      //    reject it, because V8 itself produced it.
      const { w: donorWindow, marker: donorMarker } = await runPreload(donorPath);
      expect(donorMarker).to.equal('DONOR');
      const donorCacheFile = cacheFileFor(donorPath);
      // The write is fire-and-forget on the thread pool (preload_code_cache.cc:135-139).
      await waitFor(
        () => fs.existsSync(donorCacheFile) && fs.statSync(donorCacheFile).size > HEADER_LENGTH,
        donorCacheFile
      );
      const donorClosed = once(donorWindow, 'closed');
      donorWindow.destroy();
      await donorClosed;

      const donorBlob = fs.readFileSync(donorCacheFile).subarray(HEADER_LENGTH);
      expect(donorBlob.length).to.be.greaterThan(0);

      // 2. Plant the donor's blob under the VICTIM's cache key, paired with the
      //    victim's own correct source hash. This is precisely the pair a
      //    compromised renderer sends over SetPreloadCodeCache: a hash it can
      //    compute for free (the real preload source is handed to it in
      //    RendererStartupData) and a blob of its choosing.
      const victimHash = crypto.createHash('sha256').update(fs.readFileSync(victimPath)).digest();
      expect(victimHash).to.have.lengthOf(SHA256_LENGTH);
      fs.mkdirSync(cacheDir, { recursive: true });
      fs.writeFileSync(cacheFileFor(victimPath), Buffer.concat([MAGIC, victimHash, donorBlob]));

      // 3. First-ever load of the victim path in this browser process, so the
      //    in-memory tier is cold and the planted file is read from disk. The
      //    stored hash matches the victim's real source, so Get() serves the
      //    donor's blob; V8's length-only source check accepts it.
      const { marker: victimMarker } = await runPreload(victimPath);
      expect(victimMarker).to.equal(
        'VICTM',
        'the planted donor bytecode must not have been executed in place of the victim preload'
      );
    });

    it.skip('recompiles from source when the cached blob has been tampered with', async () => {
      // NOTE — POLARITY EXCEPTION. Unlike every other test in this file, this one
      // is expected to PASS on the current tree. It is included to BOUND the
      // claim above, not to prove it: V8's SerializedCodeData sanity check does
      // include a checksum over the payload, so a random byte flip inside the
      // blob IS caught and the preload recompiles from source. That is exactly
      // why the substitution test above uses a genuine donor blob instead of a
      // corrupted one — a byte-flip test would not demonstrate B1. Kept `.skip`ped
      // with the rest of the file; unskip it alongside the test above if you want
      // to see both halves.
      const donorPath = makePreload('DONOR');
      const victimPath = makePreload('VICTM');

      const { w: donorWindow } = await runPreload(donorPath);
      const donorCacheFile = cacheFileFor(donorPath);
      await waitFor(
        () => fs.existsSync(donorCacheFile) && fs.statSync(donorCacheFile).size > HEADER_LENGTH,
        donorCacheFile
      );
      const donorClosed = once(donorWindow, 'closed');
      donorWindow.destroy();
      await donorClosed;

      // Keep 'EPC1' and the sha256 header intact so only the BLOB changes; the
      // browser-side parse (preload_code_cache.cc:61-74) and hash comparison
      // (:103) both still succeed, and the tampered bytes reach V8.
      const tampered = fs.readFileSync(donorCacheFile);
      for (let i = HEADER_LENGTH; i < Math.min(HEADER_LENGTH + 64, tampered.length); i++) {
        tampered[i] ^= 0xff;
      }
      const victimHash = crypto.createHash('sha256').update(fs.readFileSync(victimPath)).digest();
      fs.mkdirSync(cacheDir, { recursive: true });
      fs.writeFileSync(
        cacheFileFor(victimPath),
        Buffer.concat([MAGIC, victimHash, tampered.subarray(HEADER_LENGTH)])
      );

      const { marker } = await runPreload(victimPath);
      expect(marker).to.equal('VICTM', 'tampered bytecode must be rejected and the preload compiled from source');
    });
  });

  describe('cookies.get({ domain }) subdomain matching', () => {
    // Finding:  SECURITY-REVIEW.md low-severity table, "Cookie domain filter
    //           direction inverted" (LOW, downgraded from MEDIUM; see the
    //           "Severity downgrades" section).
    // Defect:   shell/browser/api/electron_api_cookies.cc:119 uses
    //           `cookie.IsDomainMatch(*str)`, which answers "would this cookie be
    //           sent to host <filter>?" — the OPPOSITE containment direction from
    //           the documented contract at docs/api/cookies.md:81-82,
    //           "Retrieves cookies whose domains match or are subdomains of
    //           `domains`". Regressed by 74c4ae0b5, which swapped out
    //           `MatchesDomain`. No breaking-change entry, and the regressed case
    //           had no test.
    // Proves:   a `cookies.get({ domain })` filter behaves as documented — which
    //           matters because a "log out everywhere" flow that enumerates by
    //           parent domain silently leaves subdomain auth cookies behind.

    // An unprefixed partition name gives an in-memory session, so nothing is
    // written to disk and no cleanup between tests is needed.
    const makeSession = () => session.fromPartition('security-review-cookies-' + crypto.randomUUID());

    it.skip('returns a host-only subdomain cookie for a parent-domain filter', async () => {
      // EXPECTED TO FAIL until the cookie domain filter inversion is fixed; remove .skip to reproduce
      const { cookies } = makeSession();
      const name = 'security-review-host-only';

      // Omitting `domain` produces a host-only cookie, i.e. domain === 'sub.example.com'.
      await cookies.set({ url: 'https://sub.example.com/', name, value: '1' });

      // Per docs/api/cookies.md:81-82 this must match: sub.example.com IS a
      // subdomain of example.com. Today `IsDomainMatch('example.com')` on a
      // host-only cookie requires exact host equality, so it is missed.
      const list = await cookies.get({ domain: 'example.com' });
      expect(list.map((c) => c.name)).to.include(name);
    });

    it.skip('does not return a parent-domain cookie for a more specific domain filter', async () => {
      // EXPECTED TO FAIL until the cookie domain filter inversion is fixed; remove .skip to reproduce
      //
      // THE INTENDED CONTRACT FOR THIS DIRECTION MUST BE DECIDED before this
      // test is unskipped as a regression test. Read literally, the documented
      // contract ("domains match or are subdomains of `domains`") excludes this
      // cookie: `.example.com` is not `sub.example.com` and is not a subdomain of
      // it. That is what the pre-74c4ae0b5 `MatchesDomain` did, and it is what is
      // asserted here. If the project instead decides the current
      // `IsDomainMatch` direction is the desired contract, then the fix is to
      // docs/api/cookies.md plus a breaking-change entry, this test should be
      // deleted, and the test above should be re-expressed against the new
      // wording. Either way the current state — code and docs disagreeing, with
      // no test either way — is the finding.
      const { cookies } = makeSession();
      const name = 'security-review-domain-cookie';

      // A domain cookie: normalized with a leading dot, valid for subdomains.
      await cookies.set({ url: 'https://example.com/', domain: '.example.com', name, value: '1' });

      const list = await cookies.get({ domain: 'sub.example.com' });
      expect(list.map((c) => c.name)).to.not.include(name);
    });
  });

  describe('webRequest filter with an unparsable URL pattern', () => {
    // Finding:  SECURITY-REVIEW.md low-severity table, "webRequest listener
    //           registered after a pattern parse error" (LOW, downgraded from
    //           MEDIUM because it needs both a malformed pattern and an app that
    //           swallows the TypeError).
    // Defect:   shell/browser/api/electron_api_web_request.cc:722-723 calls
    //           RequestFilter::AddUrlPatterns (:261-278), which on a parse
    //           failure calls `args->ThrowTypeError(...)` and returns. That only
    //           SCHEDULES a V8 exception — `AddUrlPatterns` is `void` and the
    //           caller keeps running all the way to :746, where the listener is
    //           stored with whatever patterns happened to parse before the
    //           failure. The `filter_types` loop at :725-733 gets this right
    //           (it returns from the caller); the URL-pattern path does not.
    // Proves:   a registration call that throws leaves no listener behind, so an
    //           app that catches the TypeError and believes registration failed
    //           is not silently running a half-configured blocking listener.

    let server: http.Server;
    let serverUrl: string;
    let requestCount: number;

    before(async () => {
      server = http.createServer((req, res) => {
        requestCount++;
        res.end(req.url);
      });
      serverUrl = (await listen(server)).url;
    });

    after(() => {
      server.close();
    });

    beforeEach(() => {
      requestCount = 0;
    });

    it.skip('registers no listener at all when a URL pattern fails to parse', async () => {
      // EXPECTED TO FAIL until the webRequest pattern-parse fail-open is fixed; remove .skip to reproduce
      const ses = session.fromPartition('security-review-webrequest-' + crypto.randomUUID());
      defer(() => {
        ses.webRequest.onBeforeRequest(null);
      });

      let called = false;
      const listener = (
        _details: Electron.OnBeforeRequestListenerDetails,
        callback: (response: Electron.CallbackResponse) => void
      ) => {
        called = true;
        callback({ cancel: true });
      };

      // The patterns are collected into a std::set<std::string>
      // (electron_api_web_request.cc:688) and iterated in sorted order, so the
      // http:// pattern ('h') is parsed and added BEFORE the malformed one ('n')
      // throws. The listener that survives is therefore live and armed with a
      // pattern that matches the request made below.
      expect(() => {
        ses.webRequest.onBeforeRequest({ urls: [`${serverUrl}/filter/*`, 'not a valid pattern'] }, listener);
      }).to.throw(/Invalid url pattern/);

      // The app caught the TypeError and believes nothing is registered. Nothing
      // should be. The fetch result is captured rather than awaited bare so that
      // the surviving listener's `cancel: true` surfaces as a readable assertion
      // instead of an opaque network error.
      const result = await ses.fetch(`${serverUrl}/filter/test`, { bypassCustomProtocolHandlers: true }).then(
        (res) => ({ ok: res.ok, error: null as Error | null }),
        (error: Error) => ({ ok: false, error })
      );

      expect(called).to.equal(false, 'a listener must not be registered when the filter throws');
      const cancelled = result.error ? result.error.message : null;
      expect(cancelled).to.equal(null, 'the request must not be cancelled by a listener that failed to register');
      expect(result.ok).to.equal(true);
      expect(requestCount).to.equal(1, 'the request should have reached the server');

      // Control: registration is not simply broken — a subsequent correct call
      // does take effect. This half passes both before and after the fix.
      let calledAfter = false;
      ses.webRequest.onBeforeRequest({ urls: [`${serverUrl}/filter/*`] }, (_details, callback) => {
        calledAfter = true;
        callback({ cancel: true });
      });
      await expect(
        ses.fetch(`${serverUrl}/filter/test`, { bypassCustomProtocolHandlers: true })
      ).to.eventually.be.rejected();
      expect(calledAfter).to.equal(true);
    });
  });

  describe('C6 — webContents.ipc scoping under reentrant dispatch', () => {
    // Finding:  SECURITY-REVIEW.md C6, "Shared module-global IPC emitter array"
    //           (MEDIUM).
    // Defect:   lib/browser/ipc-dispatch.ts:41-59 — `cachedIpcEmitters` is a
    //           single MODULE-LEVEL array that getIpcEmittersForFrameEvent()
    //           mutates in place and returns. It is iterated lazily with `for...of`
    //           at :75-77 (and again at :146-148 and :170-173), so a dispatch that
    //           re-enters between two iterations rewrites index 1 to a DIFFERENT
    //           WebContents' `ipc`, and the remainder of the first dispatch is
    //           delivered to the wrong WebContents. Introduced by c0422d7cc; before
    //           that the array was one closure per WebContents. Only the
    //           `-ipc-invoke` path is safe, because it spreads into a fresh array
    //           at :105.
    // Proves:   the documented scoping contract of `webContents.ipc`
    //           (docs/api/web-contents.md:2397-2399, "An IpcMain scoped to just
    //           IPC messages sent from this WebContents") holds even when a second
    //           dispatch runs inside the first — which is exactly the guarantee an
    //           app relies on when it uses `webContents.ipc` INSTEAD of checking
    //           `event.senderFrame`.
    //
    //           Note the direction of the leak: it is not that A's handler sees
    //           B's message. A's dispatch, resumed after the re-entry, delivers
    //           A's message to B's `ipc`. Both directions violate the same
    //           contract, so the assertion below is the general one: every
    //           delivery to a `webContents.ipc` must have `event.sender` equal to
    //           that WebContents.

    afterEach(closeAllWindows);

    const CHANNEL = 'security-review-ipc-scope';

    const makeWindow = async () => {
      const w = new BrowserWindow({
        show: false,
        webPreferences: { nodeIntegration: true, contextIsolation: false }
      });
      await w.loadURL('about:blank');
      return w;
    };

    it.skip('never delivers a message from one WebContents to the ipc of another', async () => {
      // EXPECTED TO FAIL until C6 (shared module-global IPC emitter array) is fixed; remove .skip to reproduce
      const a = await makeWindow();
      const b = await makeWindow();

      const deliveries: Array<{ receiver: number; sender: number }> = [];
      a.webContents.ipc.on(CHANNEL, (event) => {
        deliveries.push({ receiver: a.webContents.id, sender: event.sender.id });
      });
      b.webContents.ipc.on(CHANNEL, (event) => {
        deliveries.push({ receiver: b.webContents.id, sender: event.sender.id });
      });

      // Capture a real, live IpcMainEvent originating from B.
      const bEvent = await new Promise<Electron.IpcMainEvent>((resolve) => {
        b.webContents.ipc.once(CHANNEL, resolve);
        b.webContents.executeJavaScript(`require('electron').ipcRenderer.send('${CHANNEL}'); void 0;`);
      });

      // Re-enter the dispatcher from index 0 of A's emitter list (A's
      // mainFrame.ipc), between iteration 0 and iteration 1 of the `for...of` at
      // ipc-dispatch.ts:75-77.
      //
      // In production the re-entry comes from a NESTED NATIVE RUN LOOP inside an
      // IPC handler — dialog.showMessageBoxSync, which reaches
      // shell/browser/ui/message_box_gtk.cc:182 gtk_dialog_run() or
      // shell/browser/ui/message_box_mac.mm:121 [alert runModal] — while a second
      // renderer's message is dispatched. See the companion test below for that
      // shape. A spec cannot dismiss a modal dialog, so this test re-emits B's
      // captured event on the shared Session instead. That is the SAME code path:
      // addIpcDispatchListeners is registered once per Session
      // (lib/browser/api/session.ts:26) and both windows use the default session,
      // so this is a second '-ipc-message' dispatch running inside the first —
      // deterministically, and with a genuine event whose `sender` really is B.
      let reentered = false;
      a.webContents.mainFrame.ipc.on(CHANNEL, () => {
        if (reentered) return;
        reentered = true;
        (a.webContents.session as NodeJS.EventEmitter).emit('-ipc-message', bEvent, CHANNEL, []);
      });

      deliveries.length = 0;
      await a.webContents.executeJavaScript(`require('electron').ipcRenderer.send('${CHANNEL}'); void 0;`);
      await waitUntil(() => deliveries.length >= 2);
      expect(reentered).to.equal(true, 'the nested dispatch did not run');

      for (const delivery of deliveries) {
        expect(delivery.sender).to.equal(
          delivery.receiver,
          `webContents #${delivery.receiver}.ipc received a message sent by webContents #${delivery.sender}`
        );
      }
    });

    it.skip('never delivers across WebContents while a modal dialog pumps a nested run loop', async () => {
      // EXPECTED TO FAIL until C6 (shared module-global IPC emitter array) is fixed; remove .skip to reproduce
      //
      // !! MANUAL ONLY — DO NOT UNSKIP THIS IN CI. !!
      // dialog.showMessageBoxSync blocks the browser process in a nested native
      // run loop until a human (or UI automation) clicks the button. Run
      // unattended, this test HANGS until the mocha timeout. It is kept because
      // it is the real-world trigger the finding describes, and because it is the
      // only formulation that produces the re-entry through a supported public
      // API rather than by re-emitting a captured event.
      //
      // It is also timing-dependent: B's send must land while A's dispatch is
      // parked inside the modal. Dismiss the dialog a second or so after it
      // appears, and repeat the run if the first attempt produces only one
      // delivery.
      const a = await makeWindow();
      const b = await makeWindow();

      const deliveries: Array<{ receiver: number; sender: number }> = [];
      a.webContents.ipc.on(CHANNEL, (event) => {
        deliveries.push({ receiver: a.webContents.id, sender: event.sender.id });
      });
      b.webContents.ipc.on(CHANNEL, (event) => {
        deliveries.push({ receiver: b.webContents.id, sender: event.sender.id });
      });

      let spun = false;
      a.webContents.mainFrame.ipc.on(CHANNEL, () => {
        if (spun) return;
        spun = true;
        // Queue B's message first so it is waiting to be dispatched by the
        // nested run loop the modal is about to start.
        b.webContents.executeJavaScript(`require('electron').ipcRenderer.send('${CHANNEL}'); void 0;`);
        dialog.showMessageBoxSync(a, {
          message: 'security-review-spec: dismiss me to continue',
          buttons: ['OK']
        });
      });

      await a.webContents.executeJavaScript(`require('electron').ipcRenderer.send('${CHANNEL}'); void 0;`);
      await waitUntil(() => deliveries.length >= 2, { timeout: 60000 });

      for (const delivery of deliveries) {
        expect(delivery.sender).to.equal(
          delivery.receiver,
          `webContents #${delivery.receiver}.ipc received a message sent by webContents #${delivery.sender}`
        );
      }
    });
  });
});
