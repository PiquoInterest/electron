# Electron Security Review

**Repository:** `/home/user/electron` · **HEAD:** `0c5e210d3` · **Review date:** 2026-07-25

## Scope and method

**Static scope:** 839 C++ source files under `shell/`, 118 TypeScript files under `lib/`, and all
248 patch files under `patches/` (13 targets: chromium 160, node 58, nan 11, reclient-configs 5,
v8 4, boringssl 2, ReactiveObjC 2, webrtc 1, squirrel.mac 1, sqlite 1, perfetto 1, ffmpeg 1,
devtools_frontend 1).

**Historical scope:** all 2,315 commits from 2024-07-25 to 2026-07-25, split into four windows,
plus a dedicated supply-chain history sweep and a fix-regression check.

**Method:** 20 parallel subagent audits — 14 covering static subsystems (browser API core,
sessions/permissions, shell/external protocol, devices, net/protocol, asar/fuses, gin
converters, context bridge, devtools/extensions/OSR, renderer TypeScript, browser TypeScript,
patches, CI state, supply-chain history), 4 covering commit windows, 1 supply-chain history
sweep, 1 fix-regression verification. Findings were then handed to 3 adversarial refutation
agents whose instruction was to **default to refuted** and only confirm what they could
re-derive from source. Every line number below was re-read at HEAD. One finding was retracted
outright and nine were downgraded as a result; those are documented in
[Corrected and withdrawn](#corrected-and-withdrawn).

**Result:** 69 confirmed findings — 1 critical, 5 high, 23 medium, 40 low — plus ~14 informational
observations and a substantial set of verified-clean negatives.

---

## Summary table

Critical, High and Medium findings. The 40 Low findings are tabulated in
[Low-severity findings](#low-severity-findings) rather than repeated here.

| Severity | Finding | Location | Precondition |
|---|---|---|---|
| CRITICAL¹ | Fork-PR code execution on self-hosted runners + unverified shared source cache | `.github/workflows/build.yml:40`, `apply-patches.yml:61-79`, `.github/actions/restore-cache-aks/action.yml` | Ability to open a PR (see ¹) |
| HIGH | Preload V8 code-cache poisoning via renderer-supplied hash | `electron_web_contents_utility_handler_impl.cc:97-109`, `preload_code_cache.cc:103` | Prior renderer compromise (native code exec) |
| HIGH | Renderer-controlled session partition name | `electron_api_session.cc:1760`, `lib/browser/guest-view-manager.ts:45` | `webviewTag: true` (not default) |
| HIGH | asar integrity validation skipped in macOS helper processes | `shell/common/asar/archive_mac.mm:24`, `archive.cc:236` | macOS; local write to app bundle |
| HIGH | `serial.forget()` dereferences an end iterator | `serial_chooser_context.cc:135-158` | Page holds a SerialPort; device unplug |
| HIGH | Site-isolation drag-target check patched to `return true` | `patches/chromium/webview_cross_drag.patch` | Any frame that can start an HTML5 drag |
| MEDIUM | External-protocol navigation grants by default (worst case of fail-open permissions) | `electron_browser_client.cc:1026,1090`, `electron_permission_manager.cc:228` | No `setPermissionRequestHandler` (default) |
| MEDIUM | Legacy `getUserMedia` desktop capture bypasses display-media handler | `web_contents_permission_helper.cc:49-58,105-119` | Default config; proven by Electron's own test |
| MEDIUM | WebUI factory matches host without checking scheme² | `electron_web_ui_controller_factory.cc:25-35` | Attacker controls a host named `accessibility` (LAN) |
| MEDIUM | `<webview>` attach accepts an unvalidated embedder frame token | `web_view_guest_delegate.cc:41`, `electron_api_web_contents.cc:4040` | `webviewTag: true` |
| MEDIUM | `WebFrameMain::ExecuteJavaScript` missing null guard | `electron_api_web_frame_main.cc:237` | App calls `executeJavaScript` during navigation |
| MEDIUM | Shared module-global IPC emitter array | `lib/browser/ipc-dispatch.ts:41-59` | App relies on `webContents.ipc` scoping + modal dialog |
| MEDIUM | Bluetooth service allowlist is a `NOTIMPLEMENTED()` stub | `electron_bluetooth_delegate.cc:106-144` | Page already holds a `BluetoothDevice` |
| MEDIUM | One Bluetooth serial grant matches every Bluetooth port | `electron_browser_context.cc:274-306` | macOS/Linux; one prior BT-SPP grant |
| MEDIUM | Serial revocation leaves open ports live | `electron_serial_delegate.h:63` | App or page calls `forget()` on an open port |
| MEDIUM | FSA sensitive-entry decision keyed by path, not origin | `file_system_access_permission_context.cc:700-710` | Two origins racing for one path |
| MEDIUM | FSA permission revocation is dead code³ | `file_system_access_web_contents_helper.cc` (whole file) | Any FSA grant |
| MEDIUM | `app.isPackaged` spoofable by renaming a signed exe | `electron_api_app.cc:916-927`, `node_bindings.cc:509-519` | Local file write next to the app |
| MEDIUM | `ELECTRON_DISABLE_SANDBOX` ungated and undocumented | `electron_main_delegate.cc:97-100,199-200` | Local control of launch environment |
| MEDIUM | V8 snapshot checksum incompatible with browser-snapshot fuse | `electron_main_delegate.cc:129-141,391-399` | Two fuses enabled together |
| MEDIUM | Context-bridge throws build Errors in the wrong realm | `electron_api_context_bridge.cc:1114`, `:761` | Hostile main world + preload error handling |
| MEDIUM | Context-bridge array element `ToLocalChecked()` aborts | `electron_api_context_bridge.cc:391` | One bridged function of any signature |
| MEDIUM | DevTools context menu UAF during blocking macOS menu | `devtools_context_menu.cc:80`, `inspectable_web_contents_view.cc:204` | macOS; DevTools open |
| MEDIUM | DevTools save-to-file writes to a stale path | `electron_api_web_contents.cc:4538` | DevTools open; user saves twice |
| MEDIUM | Notification service stores a raw `RenderFrameHost*` | `patches/chromium/notification_provenance.patch` | Compromised renderer holds the mojo pipe |
| MEDIUM | Guest-identity `CHECK_EQ` in `CreateNewWindow` commented out | `patches/chromium/chore_partial_revert_of.patch` | `window.open()` from inside a `<webview>` |
| MEDIUM | Crashpad client PID spoofing check `#if 0`'d | `patches/chromium/crashpad_pid_check.patch` | Windows; compromised renderer or local process |
| MEDIUM | `<webview>` fullscreen Escape loop never advances | `patches/chromium/webview_fullscreen.patch` | Page in `<webview>` enters fullscreen |
| MEDIUM | AI manager dereferences a null/stale RFH | `shell/browser/ai/proxying_ai_manager.cc:55-81` | App called `session.registerLocalAIHandler()` |

¹ Severity is contingent on a GitHub repo setting that cannot be read from the tree — see
[CI and supply chain](#a-ci-and-supply-chain). The cache-integrity half holds unconditionally.
² Severity depends on an unresolved upstream question — see the finding.
³ Rated LOW-MEDIUM by refutation: a missing hardening, not an introduced regression.

---

## Confirmed findings

### A. CI and supply chain

#### A1. Fork-PR code execution on self-hosted runners, into an unverified shared source cache — CRITICAL¹

**What's wrong.** `.github/workflows/build.yml:40` triggers on a bare `pull_request:`. The
`checkout-linux` job runs on the self-hosted `electron-arc-centralus-linux-amd64-32core` pool,
in a container with `options: --user root`, with two host paths mounted read-write:
`/mnt/cross-instance-cache` (the persistent shared Chromium source cache) and `/var/run/sas`
(the Azure SAS-token-minting sidecar socket). It then executes files from the PR checkout.

**Attacker path.** Open a pull request. The composite action executes PR-head code directly —
no `uses: ./` resolution debate is required:

```
node src/electron/script/generate-deps-hash.js        # .github/actions/checkout/action.yml:30
node script/yarn.js install                           # install-dependencies/action.yml:9,21,39
python3 src/electron/script/export_all_patches.py     # :115
node ./script/patch-up.js                             # :120
```

Any one of those is root-level code execution on the build fleet. `.github/workflows/apply-patches.yml`
is a second door to the same primitive: it correctly checks out the base ref at `:61-67`, then
`git merge --squash FETCH_HEAD` of the PR head at `:68-77`, and only *afterwards* runs
`uses: ./src/electron/.github/actions/checkout` at `:78-79` — against the now attacker-influenced
tree.

Every gate was traced and is trivially satisfied:

- `if: github.repository == 'electron/electron'` is **true** for fork PRs — on a `pull_request`
  event `github.repository` is the base repo. Its actual purpose is to stop the workflow running
  on forks' own pushes.
- `needs.setup.outputs.src` is a negated brace pattern excluding only `docs/`, `.claude/` and PGO,
  so any PR touching one non-docs file sets it; a **docs-only PR still runs** via the second
  disjunct `docs-only == 'true'`.
- `apply-patches.yml`'s `has-patches` gate matches `DEPS` or `patches/**` — add any trivial file
  under `patches/` alongside the payload.
- `grep -rn "fork|head\.repo|isFork|full_name" .github/` returns exactly one hit repo-wide:
  `pr-template-check.yml:15`. There is no `head.repo.fork` check, no `author_association` check,
  and no `environment:` on any checkout or build job.

**The cache-poisoning half holds regardless.** `restore-cache-aks/action.yml` (49 lines, read in
full) verifies that the tarball exists, that `du != 0`, and that `src/third_party/blink` is a
directory. Nothing else. A grep for
`sha256|sha512|gpg|--verify|checksum|attest|signature|hmac|cosign` across `restore-cache-aks/`,
`restore-cache-azcopy/`, `checkout/` and `build-git-cache/` returns **zero matches**.
`release-build.yml:86` sets `GCLIENT_EXTRA_ARGS` byte-identical to `build.yml:175`, both use the
`v2-src-cache-` prefix and the same mount, so PR builds and release builds share one cache
namespace. `generate-deps-hash.js` hashes only `DEPS`, `yarn.lock`, `sysroots.json`,
`checkout/action.yml`, all of `patches/` and `GCLIENT_EXTRA_ARGS` — all public, so the DEPSHASH is
**precomputable** and an attacker can pre-seed an entry a future release build will consume.
`clean-src-cache.yml:61` is exactly `find /mnt/cross-instance-cache -type f -mtime +15 -delete`,
so a poisoned tree persists 15 days. `linux-publish.yml:60` and
`pipeline-segment-electron-publish.yml:185-187` consume it.

**Precondition and residual.** The effective mitigation is
Settings → Actions → "Fork pull request workflows from outside collaborators", which is not stored
in-tree. The public-repo default is *first-time contributors only* — meaning anyone with one prior
merged PR runs automatically. If the repo is set to the stricter "require approval for all outside
collaborators", the code-execution half drops to MEDIUM. **The cache-integrity gap holds either
way.** No ruleset or branch-protection artifact exists anywhere under `.github/`.

**Partial detective control (not a mitigation).** `non-maintainer-dependency-change.yml:4-11`
fires on `pull_request_target` for `.github/workflows/**`, `.github/actions/**`, `yarn.lock`,
`.yarn/**` and `.yarnrc.yml` from non-MEMBER/OWNER authors and posts a "request changes" review.
It does not block CI, it fires *after* the build starts, and it does not cover `script/**`.

**Fix.** Do not run fork-PR code on runners that mount the shared cache or the SAS socket; mount
`/mnt/cross-instance-cache` read-only for PR builds; resolve local composite actions from the base
ref; HMAC each cache tarball with a key unavailable to fork-PR runs and verify on restore.

#### A2. CODEOWNERS infra sign-off removed — LOW *(downgraded from MEDIUM)*

`75c9a16f7` "chore: do not require infr singoff for github workflows/actions (#51738)"
(2026-05-21) deleted exactly four lines from `.github/CODEOWNERS`:

```
-/.github/actions/                       @electron/wg-infra
-/.github/workflows/*-publish.yml        @electron/wg-infra
-/.github/workflows/build.yml            @electron/wg-infra
-/.github/workflows/pipeline-*.yml       @electron/wg-infra
```

Those entries had themselves been added in-window by `4874233aa` (2024-08-21). At HEAD `/.claude/`
is the only remaining Infra WG path. Separately, `.github/CODEOWNERS:16` still names
`/lib/browser/devtools.ts @electron/wg-security` — **a file deleted by `e63f18647`**; the
privileged logic moved to `shell/browser/ui/devtools_context_menu.cc` and
`inspectable_web_contents.cc`, which no CODEOWNERS rule covers.

Downgraded because CODEOWNERS is advisory unless a branch protection rule or ruleset enables
"Require review from Code Owners", and no such artifact is visible from the repository. The
"stealth commit" framing in the original finding is **unsupported and has been dropped**: empty
commit bodies are this repo's norm and the change went through a numbered, reviewed PR from a
long-standing maintainer. Raise with the Infra WG only if code-owner review was in fact enforced;
restore the dead `devtools.ts` rule against its successor files regardless.

#### A3. Homebrew pinning and notarization check removed from the macOS release path — LOW

`c2a0ec993` "ci: unpin homebrew version (#51757)" (2026-05-24) reverted `05fc998e5` after 17 days.
The deleted action pinned Homebrew to 5.1.10, verified SHA-256 `ece2e1c1…2462` via
`shasum -a 256 -c`, ran `spctl -a -vv --type install` (Gatekeeper/notarization) before
`sudo installer`, and set `HOMEBREW_NO_AUTO_UPDATE=1`. `brew install azcopy` now runs unpinned in
the macOS publish path at `pipeline-segment-electron-publish.yml:159`, with auto-update re-enabled.

#### A4. Untrusted input moved back into a `run:` block — LOW

`d430d00f0` "ci: replace actions-cool/issues-helper usage (#51447)" (2026-05-04) moved a comment
body from an action `with:` input (data, never shell-parsed) into a `run:` heredoc, reintroducing
`${{ github.event.pull_request.user.login }}` inside a shell script — the exact pattern
`9928c7d82` "chore: harden GitHub Actions against script injection patterns (#50512)" removed
repo-wide roughly six weeks earlier, including the identical `user.login` case. Not exploitable
(GitHub logins are `[A-Za-z0-9-]{1,39}`), but it is a measurable regression of a deliberate
hardening pass.

#### A5. Residual `run:`-block interpolations — INFO

`pull-request-labeled.yml:73`, `issue-labeled.yml:87` and `issue-opened.yml:157` still interpolate
`${{ github.event.*.user.login }}` directly into `run:` bodies. Inert for two independent reasons:
the login charset, and the fact that all three sit inside a single-quoted heredoc (`<<'EOF'`) where
the shell performs no expansion at all.

---

### B. High

#### B1. Preload V8 code-cache poisoning via a renderer-supplied source hash — HIGH

*(Downgraded from CRITICAL: there is no JavaScript surface for this mojo call, so a prior renderer
compromise is required.)*

**What's wrong.** `ElectronWebContentsUtilityHandlerImpl::SetPreloadCodeCache` accepts *both* the
V8 code-cache blob and its claimed source hash from the renderer, and the browser stores them
together:

```cpp
// shell/browser/electron_web_contents_utility_handler_impl.cc:97-109
void ElectronWebContentsUtilityHandlerImpl::SetPreloadCodeCache(
    const std::string& id,
    const std::vector<uint8_t>& source_hash,
    mojo_base::BigBuffer cache) {
  // ...
  // |source_hash| must come from the renderer — only it knows which source
  // the blob was compiled from; hashing the file here would race a
  // concurrent preload change and pin a stale blob under the new hash.
  if (!IsPreloadIdServedToFrame(GetRenderFrameHost(), id))
    return;
  preload_code_cache::Set(id, source_hash, base::span<const uint8_t>(cache));
}
```

`IsPreloadIdServedToFrame` validates the **cache key**, never the **provenance** of the blob.
`preload_code_cache::Get()` then serves the blob whenever the stored hash matches the real source:

```cpp
// shell/browser/preload_code_cache.cc:103
if (!entry || entry->source_hash != crypto::hash::Sha256(contents))
  return {};
return entry->blob;
```

So the renderer sends `Set(valid_id, sha256(REAL preload source), ATTACKER blob)` and the browser
serves the attacker's bytecode as the preload from then on.

**No V8 backstop.** Verified against upstream V8: `SerializedCodeData::SourceHash` is a 29-bit
source-length field plus a has-wrapped-arguments bit and an is-module bit. There is **no content
hash**. Electron's own mojom comment says so
(`shell/common/api/api.mojom` / `web_contents_utility.mojom:24-29`): "V8's own CachedData source
check is length-only, so it cannot reject a same-length source change." The chosen mitigation — a
source hash — is supplied by the untrusted party.

**Aggravating detail the original finder missed.** The renderer is *handed the real preload source*
in `RendererStartupData`. Computing `sha256(real source)` and padding the malicious source to an
identical length is therefore free — no guessing, no oracle.

**Amplifiers, all re-verified at HEAD.**

- The interface is registered **outside** the gate that wraps `mojom::ElectronApiIPC`. At
  `shell/browser/electron_browser_client.cc:1633-1647` `ElectronApiIPC` is added only when the RFH
  is the primary main frame or `AllowsNodeIntegrationInSubFrames()`; at `:1650` the
  `mojom::ElectronWebContentsUtility` `AddInterface` sits after that `if` block closes and runs for
  **every** `RenderFrameHost`. A cross-origin OOPIF that was never served the preload can write the
  entry.
- The cache is **not partitioned**: the in-memory map is keyed only by `id`, and `PathForId`
  (`preload_code_cache.cc:50-59`) builds `chrome::DIR_USER_DATA` + `"preload-"` + path. An entry
  poisoned from a low-privilege session is served to a high-privilege window using the same preload
  path.
- It **persists to disk** (`<userData>/Code Cache/electron-preload/<sha256(id)>.cache`), so the
  compromise survives app restart. Disk read-back validates only a 4-byte `EPC1` magic and a
  minimum length.
- It **bypasses the `EnableEmbeddedAsarIntegrityValidation` fuse** — the integrity-checked source
  is never executed, only the unvalidated bytecode.
- No fuse gates it, and it is active whenever the WebContents runs sandboxed — the default since
  Electron 20. It is the **only** new renderer→browser mojo method in the entire 789-commit final
  window.

**Impact.** A one-shot renderer compromise becomes persistent code execution *as the preload*, in
the preload's isolated world, with `ipcRenderer`/`contextBridge`/`webFrame`, surviving restart and
defeating context isolation for every bridged API.

**Fix.** Best formulation: have the browser compute `sha256(contents)` when it reads the preload
for the push, hand that hash to the renderer in `PreloadScriptData`, and require the renderer to
**echo it back** — `Set()` then accepts only a blob whose echoed hash equals the browser's own
recorded hash for the exact bytes it served. This closes the "browser can't hash without racing"
objection without trusting the renderer. Additionally: partition per `BrowserContext`, and gate the
interface the way `ElectronApiIPC` is gated.

*(Service-worker preload realms are unaffected: `CreatePreloadScript` skips the ship-back when
`render_frame == nullptr` and `IsPreloadIdServedToFrame` only accepts `kWebFrame` ids.)*

#### B2. Renderer-controlled session partition name — HIGH

**What's wrong.** `Session::FromPartition` (`shell/browser/api/electron_api_session.cc:1760`)
performs no character validation on a `persist:` partition name:

```cpp
} else if (partition.starts_with(kPersistPrefix)) {
  std::string name = partition.substr(8);
  browser_context = ElectronBrowserContext::From(name, false, std::move(options));
```

The name becomes an on-disk path via `MakePartitionName` → `base::EscapePath`
(`electron_browser_context.cc:238-240,381-385`). `kPathCharmap` was independently decoded twice as
`0xd400002d`, and checked against upstream `base/strings/escape.cc`: `.` (0x2E) and `/` (0x2F) are
**not** escaped; `:` and `\` are. `FilePath::Append` performs no `..` normalization — only a
`DCHECK(!IsPathAbsolute())` that compiles out in release.

**Attacker path.** `lib/browser/guest-view-manager.ts:45` passes the renderer-supplied `<webview>`
partition straight through:

```ts
partition: params.partition,
```

and `partition` is **not** in the `inheritedWebPreferences` forcing map at
`guest-view-manager.ts:54-61`, which covers only `contextIsolation`, `javascript`,
`nodeIntegration`, `sandbox`, `nodeIntegrationInSubFrames` and `enableWebSQL`.

**Strengthened beyond the original finding.** `executeJavaScript` is in the webview async-method
allowlist at `lib/common/web-view-methods.ts:68`. So attacker content can create

```html
<webview partition="persist:<the app's trusted partition>" src="https://app.example.com/">
```

and then **script it**. That fully defeats partition isolation — the attacker gets the trusted
session's cookie jar, permission handlers, custom protocol handlers, proxy config and
`setCertificateVerifyProc`, and can run arbitrary JS in a document loaded in it. The traversal
variant (`persist:../../../../evil`, which forces creation of a persistent browser context with
cookies DB, Local Storage, IndexedDB, prefs and code cache **outside** the app's session-data
directory, on every platform because `/` is a separator on Windows too) is the secondary harm.

**Precondition.** `webviewTag: true`, which is **not** the default.

**Fix.** Reject partition names containing a path separator or a `..` component, or hash them
before use; and add `partition` (and `preload`) to `inheritedWebPreferences`, or apply an allowlist
to `parseWebViewWebPreferences` keys.

#### B3. asar integrity validation skipped in macOS helper processes — HIGH

**What's wrong.** `Archive::RelativePath()` on macOS computes the archive path relative to
`base::apple::MainBundlePath()` — the bundle of the *currently running* executable:

```objc
// shell/common/asar/archive_mac.mm:24-33
std::optional<base::FilePath> Archive::RelativePath() const {
  base::FilePath bundle_path = base::MakeAbsoluteFilePath(
      base::apple::MainBundlePath().Append("Contents"));
  base::FilePath relative_path;
  if (!bundle_path.AppendRelativePath(path_, &relative_path))
    return std::nullopt;
  return relative_path;
}
```

In every macOS child process that is the *helper* bundle
(`<App>.app/Contents/Frameworks/<App> Helper*.app/Contents/MacOS/<App> Helper*`),
`AppendRelativePath` fails for `<App>.app/Contents/Resources/app.asar` and this returns `nullopt`.
`archive.cc:236` gates the whole header-validation block on `RelativePath().has_value()` and sets
`header_validated_ = true` only inside it (`:254`). `GetFileInfo()`/`Stat()` then pass
`header_validated_` as the `load_integrity` argument to `FillFileInfoWithNode()`, so
`info->integrity` is never populated and **every subsequent read in that process is unvalidated**.

**Two decisive in-repo corroborations.**

1. `shell/common/mac/main_application_bundle.mm:27-45` exists precisely to correct for this — it
   walks up five levels with the comment "The running executable is the helper. Go up five steps".
   `GetResourcesPath()` (`node_bindings.cc:546`) uses that corrected function; `archive_mac.mm`
   does not. The two disagree in helpers.
2. `HeaderIntegrity()` does `CHECK(relative_path.has_value())` and reads `ElectronAsarIntegrity`
   from `[NSBundle mainBundle]`. That key exists only in the outer app's Info.plist
   (`shell/browser/resources/mac/Info.plist`); the helper plist
   (`shell/renderer/resources/mac/Info.plist`) has no such key. If `RelativePath()` *did* return a
   value in a helper, `HeaderIntegrity()` would return `nullopt` and `archive.cc:240` would
   `LOG(FATAL)` on every launch. Integrity-enabled apps do not crash in helpers, so `RelativePath()`
   must be returning `nullopt` there.

**Refutation attempt and why it fails.** The proposed rebuttal was that some `SetOverrideAppBundle`
call might make `MainBundlePath()` return the outer bundle in helpers. There is **no
`SetOverrideAppBundle` anywhere in the tree** — Electron only ever calls
`SetOverrideFrameworkBundlePath` and `SetBaseBundleIDOverride`. Child processes really do open
`app.asar` through `asar::Archive`, via the always-installed `OnNodePreload` →
`lib/node/init.ts` → `wrapFsWithAsar` path.

**Attacker path.** Local write access to `<App>.app/Contents/Resources/app.asar` (apps installed in
`~/Applications`, user-writable install dirs, self-updating apps). Modify the *body* of a JS file
only loaded in a helper process — the entry script of `utilityProcess.fork()` and anything it
requires, or renderer code under `nodeIntegration`. The archive header is untouched, so the browser
process's header check still passes and the app boots normally. Result: attacker code executes
inside the signed, notarized app with `embeddedAsarIntegrityValidation` **and**
`onlyLoadAppFromAsar` both enabled — the exact combination
`docs/tutorial/asar-integrity.md` says makes it "impossible to load non-validated code".

Windows is unaffected (`archive_win.cc:28-40` uses `base::DIR_ASSETS` and reads the resource from
`::GetModuleHandle(NULL)`, both identical in all child processes). Linux has no implementation at
all (`archive.cc:270-278` is a stub) — documented behaviour.

**Fix.** Use `electron::MainApplicationBundlePath()` (which already handles helpers) in
`Archive::RelativePath()`, and read `ElectronAsarIntegrity` from
`electron::MainApplicationBundle()` rather than `[NSBundle mainBundle]` in `HeaderIntegrity()`. Add
a regression test that tampers with a file body only read by a `utilityProcess.fork()` entry script.

#### B4. `serial.forget()` dereferences an end iterator — HIGH

**What's wrong.** `SerialChooserContext::RevokePortPermissionWebInitiated`
(`shell/browser/serial/serial_chooser_context.cc:135-162`) guards the lookup for the revocation
work, then dereferences the **same iterator outside the guard** when building the event payload:

```cpp
auto it = port_info_.find(token);
if (it != port_info_.end()) {            // :135-136
  // ...revoke...
}                                        // guard closes at :142
// ...
if (session && session->Get()) {
  // ...
  details.Set("port", it->second);       // :158  <-- `it` may be end()
```

**Attacker path — two triggers, one needing no compromise at all.**

(a) A page obtains a `SerialPort`; the user unplugs the device; `OnPortRemoved()` runs
`port_info_.erase(port->token)` (`:246`); the JS `SerialPort` object survives; `port.forget()`
arrives with a token no longer in the map.
(b) A compromised renderer calls `blink.mojom.SerialService.ForgetPort()` with any 128-bit value.

**Verified upstream:** `content/browser/serial/serial_service.cc` `ForgetPort` passes the token
straight to the delegate with **zero validation**. And the garbage pointer *is* dereferenced — the
gin converter does so immediately at `shell/common/gin_converters/serial_port_info_converter.h:21`
(`port->token.ToString()`). So `it->second` reads past the libc++ `__tree_end_node` sentinel and the
resulting `SerialPortInfoPtr` is followed to build a V8 object: a browser-process type-confused read
or controlled crash.

This is the cleanest finding in the review. Chrome's own equivalent has the `if (it != end())`
guard; the missing guard is in the **event-emit block Electron added**, making it an
Electron-introduced regression.

**Fix.** Hoist the emit inside the guard, or clone the port info while the iterator is known valid.

#### B5. Site-isolation drag-target check patched to `return true` — HIGH

**What's wrong.** `patches/chromium/webview_cross_drag.patch` replaces the entire body of
`WebContentsViewDragSecurityInfo::IsValidDragTarget`:

```diff
--- a/content/browser/web_contents/web_contents_view_drag_security_info.cc
@@ -66,7 +66,7 @@ bool WebContentsViewDragSecurityInfo::IsValidDragTarget(
   // browser-side checks only have local tree fragment ... granularity at best, but a drag
   // operation eventually targets one single frame in that local tree fragment.
-  return target_rwh->GetSiteInstanceGroup()->GetId() == site_instance_group_id_;
+  return true;
```

`IsValidDragTarget` is the single browser-side gate consulted on `DragTargetDragEnter`,
`DragTargetDragOver` and `DragTargetDrop`. Upstream it requires the drag *target*
`RenderWidgetHost` to be in the same `SiteInstanceGroup` that started the drag.

**The relaxation is not scoped to guests.** The patch header is one sentence — "This allows
dragging and dropping between `<webview>`s." — and does not acknowledge that the check is a
site-isolation control, or that it is now removed for **every OOPIF and cross-site frame**, not just
webview-to-webview. A grep of `shell/` for `IsValidDragTarget`/`DragTargetDrop`/`drag_security`/
`DropData` finds Electron-side hits only in `osr_web_contents_view.{cc,h}`. There is no compensating
same-partition or same-guest check anywhere, and nothing gates it on `webPreferences.webviewTag`.

**Attacker path.** Content in any frame that can start an HTML5 drag controls the `DropData` payload
(text, `text/html`, URLs, custom MIME data, and `filenames` for file drags). The browser now
delivers that payload to a widget in a different `SiteInstanceGroup` — a different site, a different
`<webview>`, a different `StoragePartition`. In the **file-drag direction this is worse than data
disclosure**: the drop path grants the target renderer process read access to the dropped file
paths, so a renderer that should never have file access can be handed it by a drag originating in an
unrelated view.

**Fix.** Scope rather than delete: keep the upstream comparison and add an `||` clause permitting the
cross-group case only when both `SiteInstanceGroup`s are guests sharing the same
`StoragePartitionConfig`, exposed via a new `ContentBrowserClient` hook.

---

### C. Medium

#### C1. External-protocol navigation grants by default — MEDIUM *(downgraded from HIGH; report with the permission fail-open)*

A navigation from untrusted web content to an unhandled URL scheme reaches
`platform_util::OpenExternal` (`ShellExecuteEx` / `xdg-open` / `-[NSWorkspace openURL:]`) with no
scheme blocklist, no user-gesture requirement and no confirmation UI, in the default configuration
where the app has not called `setPermissionRequestHandler`. Path:
`shell/browser/electron_browser_client.cc:1026` (`OnOpenExternal`), `:1033`
(`HandleExternalProtocolInUI`), `:1090` (`HandleExternalProtocol`) →
`shell/browser/electron_permission_manager.cc:228`.

Chromium's `ChromeContentBrowserClient` gates this on `ExternalProtocolHandler::GetBlockState()`
plus a confirm dialog. Electron replaces both with a permission request that **defaults to
granted**. A grep of all of `shell/` for `blocklist|blacklist|denylist|ExternalProtocolHandler|GetBlockState`
returns only device blocklists, the FSA path blocklist, and a no-op:
`ElectronExtensionsBrowserClient::PermitExternalProtocolHandler() {}`. `has_user_gesture` is threaded
through but never read in the null-handler branch. A hostile page setting
`location.href = 'ms-msdt:-id PCWDiagnostic /param …'` is a Follina-class primitive.

**Two corrections from refutation, both applied.** (i) The sandbox-flags gate at `:1061` sitting
inside `if (!is_primary_main_frame)` is **upstream-faithful** — the code comment cites
`chrome_content_browser_client.cc` and crbug.com/1148777, and Chrome likewise applies the sandbox
check only to non-main-frames. Presenting it as a hole was wrong. (ii) This is the most dangerous
instance of Electron's **documented** fail-open permission model, not an independent bug:
`ElectronPermissionManager` with no handler installed returns GRANTED from
`RequestPermissionsWithDetails` for every permission (`:228-252`) and `true` from
`CheckPermissionWithDetails` for everything except `DEPRECATED_SYNC_CLIPBOARD_READ` (`:358-364`),
without inspecting the requesting origin or whether the frame is a subframe. Note the default path
calls `ChildProcessSecurityPolicy::GrantSendMidiSysExMessage` on the renderer's process — midiSysex
is not merely a web capability here.

The fail-open default is documented at `docs/tutorial/security.md:283`, but `docs/api/session.md`'s
`setPermissionRequestHandler` section never mentions it, and `openExternal` is a first-class
permission at `docs/api/session.md:936,981`. `shell` is in `commonModuleList` and re-exported from
`require('electron')` in the renderer (the sandboxed-renderer list correctly omits it), so the same
sink is reachable a second way through a preload leak or `contextIsolation: false`.

**Fix.** Add a scheme blocklist mirroring Chromium's; require a user gesture; make the no-handler
default for `openExternal` deny; document the fail-open default in the `session` API page. The
Chromium-side question of whether anything blocks before Electron's handler is unanswerable without
a checkout — medium confidence on the exact reachable scheme set.

#### C2. Legacy `getUserMedia` desktop capture bypasses the display-media handler — MEDIUM (arguably HIGH)

`WebContentsPermissionHelper::MediaAccessAllowed`
(`shell/browser/web_contents_permission_helper.cc:49-58`, `:105-119`, `:154-158`) routes
`GUM_DESKTOP_VIDEO_CAPTURE`/`GUM_DESKTOP_AUDIO_CAPTURE` and `GUM_TAB_*` to
`HandleUserMediaRequest()` **before** the `DISPLAY_VIDEO_CAPTURE` branch that consults
`setDisplayMediaRequestHandler`. The legacy path never reaches the display-media handler; its only
gate is the generic permission request, which defaults to granted. With no source id, `GetScreenId()`
synthesizes `{TYPE_SCREEN, -1}` — **the entire desktop**.

The original agent could not confirm that ordinary web content reaches this path. Refutation
resolved it using Electron's own test: `spec/api-media-handler-spec.ts:397-413` — "is not called
when calling legacy getUserMedia with desktop capture constraint" — installs a
`setDisplayMediaRequestHandler` that **throws**, loads a **remote HTTP origin**, runs
`navigator.getUserMedia({video:{mandatory:{chromeMediaSource:'desktop'}}})` from page JS in a
default-config window, and asserts `ok === true`.

Tempering: the behaviour is pinned by Electron's own test, so it is intentional legacy behaviour
rather than an unknown regression. But apps that implemented `setDisplayMediaRequestHandler` believe
screen capture is gated, and `docs/api/desktop-capturer.md` presents it as the mechanism.

**Fix.** Route the legacy constraint through the display-media handler too, or document
prominently that it is not covered and require an explicit opt-in.

#### C3. WebUI factory matches host without checking scheme — MEDIUM *(partially refuted; could fall to INFO)*

```cpp
// shell/browser/electron_web_ui_controller_factory.cc:25-35
content::WebUI::TypeID ElectronWebUIControllerFactory::GetWebUIType(
    content::BrowserContext* browser_context,
    const GURL& url) {
  if (const std::string_view host = url.host();
      host == chrome::kChromeUIDevToolsHost ||
      host == chrome::kChromeUIAccessibilityHost) {
    return this;
  }
  return content::WebUI::kNoWebUI;
}
```

The factory decides WebUI-ness purely by `url.host()`. It never checks the scheme. Chrome's
`ChromeWebUIControllerFactory` does exactly the gate Electron omits —
`if (!url.SchemeIs(content::kChromeDevToolsScheme)) { return nullptr; ` — plus
`DevToolsUIBindings::IsValidFrontendURL(url)`. `content::WebUIControllerFactoryRegistry` performs no
scheme filtering of its own; the scheme gate is the embedder factory's job.

There is a real asymmetry behind it: `DevToolsUI` neuters itself
(`devtools_ui.cc:18` — `web_ui->SetBindings(content::BindingsPolicySet());`), but
`ElectronAccessibilityUI` never calls `SetBindings` and registers
`ElectronAccessibilityUIMessageHandler` (`requestWebContentsTree`, `requestNativeUITree`,
`setGlobalFlag`, …), which dumps the accessibility trees of every WebContents in the browser context
and of native windows.

**Why this is MEDIUM and not HIGH.** The decisive question — whether `content` actually grants WebUI
bindings to a frame committing an `http://` URL — is **unresolved**. `navigation_request.cc` and
`render_frame_host_impl.cc` both exceed the remote-fetch size limit and there is no Chromium
checkout, so `RenderFrameHostImpl::CreateWebUIImpl`/`AllowBindings` could not be read. The finding
also requires the attacker to control a host literally named `accessibility`, i.e. LAN name-spoofing
via LLMNR/mDNS/NBT-NS; arbitrary remote web content cannot arrange this, and a DNS search suffix does
**not** help (it does not make a single-label host resolve to an attacker under a victim's default
config in the way the original claim assumed). If content declines to grant bindings to a non-WebUI
scheme, this falls to INFO — the missing scheme check is still a real defect, but not a reachable one.

**Fix.** Gate on scheme before host, mirroring Chrome: require `devtools://` for
`kChromeUIDevToolsHost` and `chrome://` for `kChromeUIAccessibilityHost`. Add an explicit
`SetBindings` call to `ElectronAccessibilityUI` so its privilege level is stated, not inherited.

#### C4. `<webview>` attach accepts an unvalidated embedder frame token — MEDIUM *(partially refuted)*

The `<webview>` attach path takes an embedder frame token supplied by the renderer and resolves it
to a `RenderFrameHost` used as the outer frame for `AttachInnerWebContents()`. The only check that
the resolved frame belongs to the embedder WebContents is a `DCHECK_EQ`, compiled out in release,
and there is no null check:

```cpp
// shell/browser/web_view_guest_delegate.cc:35-52
int embedder_process_id = embedder_web_contents_->GetPrimaryMainFrame()
                              ->GetProcess()->GetDeprecatedID();
auto* embedder_frame = content::RenderFrameHost::FromFrameToken(
    content::GlobalRenderFrameHostToken(embedder_process_id, embedder_frame_token));
DCHECK_EQ(embedder_web_contents_,
          content::WebContents::FromRenderFrameHost(embedder_frame));   // :41-42
// ...
embedder_web_contents_->AttachInnerWebContents(
    base::WrapUnique<content::WebContents>(guest_web_contents),
    embedder_frame, /*is_full_page=*/false);
```

The chain: `lib/browser/guest-view-manager.ts:305-310` passes the renderer's `embedderFrameToken`
straight to `createGuest`; `makeSafeHandler` (`:277-291`) checks only `event.type === 'frame'` and
`isWebViewTagEnabled(event.sender)`, never comparing `event.senderFrame` to the token;
`electron_api_web_contents.cc:4040` (`WebContents::AttachToIframe`) validates only that the token is
*parseable*, and sets `attached_ = true` before delegating.

**Process pinning is a real mitigation the finder underweighted.** `embedder_process_id` comes from
the **trusted** `event.sender`'s main-frame process, so the token can only resolve to a frame in the
embedder's own process. Cross-WebContents attach therefore requires a second WebContents already
sharing that process — reachable under site isolation but not free.

**The cleanest reachable consequence is the null case the finder did not identify:** a random
well-formed token resolves to no frame, so `embedder_frame == nullptr` flows into
`AttachInnerWebContents` → browser-process null dereference.

Secondary: `attached_ = true` is set unconditionally regardless of attach success, and
`~WebContents` (`electron_api_web_contents.cc:1219`) uses `is_guest() && attached_` to decide
`ReleaseWebContents()` — ownership bookkeeping keyed on a flag that lies when the attach fails.

**Not a regression.** `git blame` attributes the `DCHECK_EQ` to `dd5b8769b` "fix: use OOPIF for
webview tag (#13869)" (Aug 2018), the commit that created `AttachToIframe`.
`git log -S 'DCHECK_EQ(embedder_web_contents_'` returns exactly one commit (a directory rename) —
one add, no delete. This is a 2018-era original gap. There is also **no spec coverage**: grep for
`attachToIframe|CREATE_AND_ATTACH_GUEST|embedderFrameToken` in `spec/` returns nothing.

**Fix.** Replace the `DCHECK_EQ` with a real early return —
`if (!embedder_frame || content::WebContents::FromRenderFrameHost(embedder_frame) != embedder_web_contents_) return;`
— assert `event.senderFrame.frameToken === embedderFrameToken` in the JS handler, and set
`attached_` only after a successful attach.

#### C5. `WebFrameMain::ExecuteJavaScript` missing null guard — MEDIUM

`shell/browser/api/electron_api_web_frame_main.cc:237` is the only method in the class gating on the
raw `render_frame_disposed_` flag instead of `HasRenderFrame()`, then unconditionally dereferencing
`render_frame_host()` — which is a token lookup, so `!disposed` does **not** imply a live RFH.
`67f5ac5bb` (#45487) fixed exactly this bug class by converting call sites to `HasRenderFrame()` but
missed `ExecuteJavaScript`; `ee67bc7dc` (#45609) then replaced the `raw_ptr` member with the
token-lookup accessor, **widening** the null window. Browser-process crash; the renderer controls
navigation timing. **Fix:** `if (!HasRenderFrame())` at `:237`.

#### C6. Shared module-global IPC emitter array — MEDIUM

`getIpcEmittersForFrameEvent` (`lib/browser/ipc-dispatch.ts:41-59`) mutates and returns a single
**module-level** array, iterated at `:75-77`, `:136-148` and `:170-173` across `emit()` calls that
run application code. `c0422d7cc` "refactor: dispatch IPC messages from Session (#45452)"
(2025-02-17) introduced this: before, the array was one closure per WebContents with index 1 fixed
to that WebContents' own `ipc`; now it is module scope, shared by every WebContents in every
Session (`lib/browser/api/session.ts:26` calls `addIpcDispatchListeners(this)` once per Session),
and both indices are rewritten on every dispatch.

Nested-run-loop reentrancy is confirmed in-tree: `shell/browser/ui/message_box_gtk.cc:182` calls
`gtk_dialog_run()`, and `shell/browser/ui/message_box_mac.mm:121,133,144,201` call
`[alert runModal]`/`[NSApp runModalForWindow:]` — with an existing comment at
`message_box_mac.mm:174-177` about not being able to control re-entrant `runModal` in user
callbacks. So `dialog.showMessageBoxSync` from an IPC handler is a real trigger. Only `-ipc-invoke`
is safe (it spreads into a fresh array at `:105`).

**Impact framing corrected by refutation:** only the *emitter* is aliased. The `event` object passed
to the handler is still the correct one, so `event.sender`/`event.senderFrame` remain truthful. The
victim is specifically an app relying on `webContents.ipc`/`webFrameMain.ipc` scoping *instead of*
checking the sender — which is exactly what those APIs are documented to make safe. Combined with
needing a precisely-timed second renderer during a modal dialog, MEDIUM is the ceiling; an earlier
escalation to MEDIUM-HIGH was unearned. **Fix:** return a fresh array.

#### C7. Bluetooth service allowlist is a `NOTIMPLEMENTED()` stub — MEDIUM

`shell/browser/bluetooth/electron_bluetooth_delegate.cc:106-144`: `HasDevicePermission()`,
`IsAllowedToAccessService()`, `IsAllowedToAccessAtLeastOneService()` and
`IsAllowedToAccessManufacturerData()` are `NOTIMPLEMENTED()` stubs that unconditionally return
`true`. These *are* the upstream permission layer — overrides of `content::BluetoothDelegate`, and
`content::WebBluetoothServiceImpl` has no fallback. `GrantServiceAccessPermission()` is likewise a
stub returning a fresh random `WebBluetoothDeviceId`, so no allowlist is ever *recorded* to check
against. Once a page holds any `BluetoothDevice`, `getPrimaryService()`/`getPrimaryServices()`
succeed for **any** GATT service UUID and `watchAdvertisements` exposes any manufacturer data — not
just what the page declared in `requestDevice()`. An app inspecting `requestDevice` filters in
`select-bluetooth-device` to decide what to approve is deciding on a promise the browser never
enforces.

#### C8. One Bluetooth serial grant matches every Bluetooth port — MEDIUM (macOS/Linux)

`shell/browser/electron_browser_context.cc:274-306` + `serial_chooser_context.cc:48-51`.
`DoesDeviceMatch()` is the sole comparator behind `CheckDevicePermission()`. For serial on
non-Windows it compares only `vendor_id`, `product_id`, `serial_number` and (macOS) `usb_driver`.
`PortInfoToValue()` writes **none** of those keys for a Bluetooth serial port — only `name` and
`bluetooth_device_path`, and `bluetooth_device_path` is never read anywhere in the tree (grep finds
exactly one use: the write). Every absent-vs-absent comparison passes and the function falls through
to `return true`. So an origin approved once for one Bluetooth SPP port can thereafter open **every**
Bluetooth serial port on the machine, with no chooser and no new event. Windows is unaffected (BT
ports never get a `device_instance_id`, so they never match).

#### C9. Serial revocation leaves open ports live — MEDIUM

`shell/browser/serial/electron_serial_delegate.h:63` — `OnPermissionRevoked(const url::Origin&)` is
an empty override that, unlike every sibling method, does not forward to `observer_list_`, and
`SerialChooserContext` never fires it on `port_observer_list_` either. So `navigator.serial.forget()`
drops the grant and emits `serial-port-revoked` to the app, but the already-open port keeps reading
and writing. The app may then hand the same physical port to a different origin via
`select-serial-port`, giving two origins concurrent access; symmetrically, an app revoking a device
in response to a security event cannot cut off the live connection.

#### C10. FSA sensitive-entry decision keyed by path, not origin — MEDIUM

`shell/browser/file_system_access/file_system_access_permission_context.cc:700-710`.
`ConfirmSensitiveEntryAccess()` coalesces in-flight blocklist decisions in `callback_map_`, keyed by
`path_info.path` **alone**; `origin` is used only for the event payload. A second requester for the
same path while a decision is outstanding is appended to the same callback vector and silently
inherits the first requester's verdict, with **no second event emitted**. Origin A (trusted)
triggers a check for path P; origin B (untrusted iframe) reaches P in that window; `inserted` is
false so B is queued and no event carrying B's origin is raised. When the app allows for A, B
receives `kAllowed` for a path the app was never asked about. This is a race, not a one-shot, and
the coalescing map is an **Electron addition** — upstream
`ChromeFileSystemAccessPermissionContext` invokes the callback per request.

#### C11. FSA permission revocation is dead code — MEDIUM *(LOW-MEDIUM after refutation)*

`976f5d1b7` "fix: File System API permissions should reset on WebContents destruction (#43009)"
shipped as a security fix and has **no effect**. It added
`shell/browser/file_system_access/file_system_access_web_contents_helper.cc` — a
`WebContentsObserver`/`WebContentsUserData` that calls `NavigatedAwayFromOrigin()` on cross-origin
top-level navigation and on `WebContentsDestroyed()`, arming a 5s timer → `CleanupPermissions()` →
`RevokeActiveGrants()`.

**`CreateForWebContents()` is never called.** Exhaustive grep confirms the symbol appears only in its
own `.h`/`.cc` plus one comment at `file_system_access_permission_context.h:124`. No macro, helper
list, or `WEB_CONTENTS_USER_DATA_KEY_IMPL` side effect attaches it — that macro only defines the key;
`content::WebContentsUserData<T>` requires an explicit call, and Electron has no `TabHelpers`
equivalent. The `CreateForWebContents` call list in `electron_api_web_contents.cc` contains
`WebContentsPermissionHelper` (`:1106`), `ElectronExtensionWebContentsObserver`,
`AutofillDriverFactory`, `PrintViewManagerElectron`, `ChildWebContentsTracker` and
`NativeWindowRelay` — not this one. `git log` shows `976f5d1b7` is the only commit ever to touch the
file.

Consequence: FSA grants live in `active_permissions_map_` keyed **by origin only**, with no
tab/frame binding, and nothing ever revokes them. GRANTED persists as long as any handle keeps the
`PermissionGrantImpl` alive — surviving cross-origin navigation away and back, and surviving
destruction of the WebContents that earned the grant. Chromium revokes after 5s once no tab holds
the origin; Electron's copy is inert. Downgraded because the consequence is Electron's *pre-existing*
behaviour: this is a missing hardening, not an introduced regression. **Fix:** call
`CreateForWebContents` from `WebContents::InitWithSessionAndOptions`, next to the existing
`WebContentsPermissionHelper::CreateForWebContents` at `:1106`.

#### C12. `app.isPackaged` spoofable by renaming a signed executable — MEDIUM

`App::IsPackaged()` (`shell/browser/api/electron_api_app.cc:916-927`) decides "packaged" purely from
the executable **base name** (on Windows, `base_name != "electron.exe"`). `SetNodeOptions()`
(`shell/common/node_bindings.cc:509-519`) uses that boolean as the only gate on the packaged-app
`NODE_OPTIONS` allowlist, and `IsAllowedOption()` (`:471-473`) uses it to gate `--expose-internals`.

A local attacker copies the victim's signed `MyApp.exe` to `electron.exe` in the same directory.
Authenticode signs PE *content*, not the filename, so the signature and any AppLocker publisher rule
still apply; `DIR_ASSETS`, `resources\app.asar` and the embedded integrity resource are unchanged, so
asar integrity and `onlyLoadAppFromAsar` still succeed and the app boots. `IsPackaged()` now returns
false, so `NODE_OPTIONS=--require \\attacker\share\evil.js` passes through untouched and executes in
the main process of a signed binary. No fuse needs flipping — `nodeOptions` is at its documented
default. **Fix:** derive "packaged" from a signal inside the signed artifact (the asar-integrity
resource, a fuse bit, a build-time constant); keep the filename heuristic only for the user-visible
`app.isPackaged` property.

#### C13. `ELECTRON_DISABLE_SANDBOX` is ungated and undocumented — MEDIUM

`shell/app/electron_main_delegate.cc:97-100` and `:199-200`: `BasicStartupComplete()`
**unconditionally** converts `ELECTRON_DISABLE_SANDBOX` into `--no-sandbox` on the browser command
line. No fuse, no packaged-app check, no `IS_MAS_BUILD()` guard. The variable is not documented in
`docs/api/environment-variables.md` — a full-tree grep finds it only in this one source file.

A local attacker who can influence the launch *environment* but not argv — macOS
LaunchAgent/LaunchDaemon `EnvironmentVariables`, `launchctl setenv`, `LSEnvironment` injection, a
modified `.desktop` file, a user-writable shell profile — disables the renderer sandbox in a signed,
notarized app on every launch. This matters most for MAS builds where (per the comment at
`shell/app/node_main.cc:142-151`) custom argv from a foreign process is discarded by macOS but the
environment is still inherited: `--no-sandbox` on the command line is *not* reachable,
`ELECTRON_DISABLE_SANDBOX` **is**. Consumed by `IsSandboxEnabled()`
(`shell/common/options_switches.cc` / `command_line_args.cc:57-60`), which
`CreateContentRendererClient()` uses to pick `ElectronRendererClient` (unsandboxed, full Node) over
`ElectronSandboxedRendererClient`. **Fix:** gate behind a fuse or at minimum `!App::IsPackaged()`;
ignore in MAS builds; document it.

#### C14. V8 snapshot checksum is incompatible with the browser-snapshot fuse — MEDIUM

`ValidateV8Snapshot()` (`shell/app/electron_main_delegate.cc:129-141`, `:391-399`) CHECKs the
SHA-256 of whatever snapshot was mapped against `kChecksum`, which `mksnapshot_checksum_gen`
(`build/checksum_header.py:30-33`, `BUILD.gn:1066-1076`) computes over exactly one file,
`v8_context_snapshot.bin`. But `GetBrowserV8SnapshotFilename()` makes the browser load
`browser_v8_context_snapshot.bin` when `loadBrowserProcessSpecificV8Snapshot` is set. There is no
second checksum and no exemption, so `embeddedAsarIntegrityValidation` and
`loadBrowserProcessSpecificV8Snapshot` **cannot both be enabled** — the browser CHECK-fails at
startup. App authors who need a browser-specific snapshot (the documented way to keep
`nodeIntegration` out of the renderer snapshot) are pushed to turn asar integrity off, losing the
local attacker's main obstacle. **Fix:** emit a second checksum and select by loaded filename, or
skip validation for that fuse in the browser process and document the trade-off.

#### C15. Context bridge builds thrown Errors in the wrong realm — MEDIUM

`shell/renderer/api/electron_api_context_bridge.cc:1114` (`ExecuteInWorld`; same defect at `:1025`,
`:1049`, `:1054`, `:1077`, `:1087`) and `:761` (`ExposeAPI`). `v8::Exception::Error()`/`ErrorThrower`
build the Error in the **currently entered** context, so its prototype, constructor and stack
accessor belong to that realm. The file scopes this deliberately everywhere else — the
`BridgeErrorTarget` enum exists purely to pick the realm (header `:17-31`: "Where the context bridge
should create the exception it is about to throw"), the recursion-limit throw enters `error_scope`
(`:167-176`), the serializer failure enters `error_scope` (`:450-462`), and `ProxyFunctionWrapper`
re-enters `calling_context` before rethrowing (`:577-582`) with a 13-line comment explaining why.
`ExecuteInWorld` and `ExposeAPI` break that invariant: their throws sit inside
`v8::Context::Scope target_scope(target_context)`, so an isolated-world caller of
`executeInMainWorld()`/`exposeInMainWorld()` receives an Error manufactured in the **main world**.

Attack: the main world pre-instruments `Error.prototype` with a setter, then forces a throw. Common
preload gadgets — `catch (e) { e.detail = internalHandle; throw e; }`, `logger.error(e.message)`,
`String(e)`, `e.stack` — invoke attacker accessors; a setter gadget hands the attacker a live
isolated-world reference, i.e. a full isolation break. Even without a gadget, `e instanceof Error` is
false in the isolated world, silently breaking preload error handling.

Two pieces of corroboration: the one throw in `ExecuteInWorld` that *is* correct (the clone-back
failure at `:1137-1141`) sits inside `Context::Scope source_scope`, proving the surrounding scope is
what selects the realm; and the project has already had to fix this exact class once —
`095e622a6` (2025-08-08) wrapped contextBridge `VideoFrame` support with
`ScriptState::ForCurrentRealm(destination_isolate)` **without entering** the destination context,
minting the wrapper in the source realm, shipped for a whole release window and fixed by `838d30510`
(#49997). The spec suite encodes the correct invariant for *values*
(`spec/api-context-bridge-spec.ts:1600-1611` asserts `obj.constructor === Object`) but nothing
asserts it for thrown Errors.

**Related open lead:** `ScriptExecutionCallback::CopyResultToCallingContextAndFinalize`
(`shell/renderer/api/electron_api_web_frame.cc:190-199`) creates its `v8::Exception::Error` with no
`v8::Context::Scope`, while the sibling paths at `:236-243` and `:250-256` explicitly enter
`promise_.GetContext()` first. Same one-line fix if it turns out Blink holds a `ScriptState::Scope`
for the target world across the callback.

#### C16. Context-bridge array element `ToLocalChecked()` aborts the renderer — MEDIUM

`shell/renderer/api/electron_api_context_bridge.cc:391` (`PassValueToOtherContextInner`, plain-array
branch) does `arr->Get(source_context, i).ToLocalChecked()`. `Get` returns an empty `MaybeLocal` when
the element read throws — an index accessor, or a Proxy/accessor reached through the prototype for a
hole — and `ToLocalChecked()` on empty is `FATAL("Attempt to access empty v8::MaybeLocal")`, an
unconditional abort in release. Every other property read in the file is defensive
(`CreateProxyForAPI` does `if (!api.Get(key, &value)) continue;`, `ExecuteInWorld` does
`if (!…ToLocal(&arg))`); the array branch is the outlier. It needs only one bridged function of any
signature:

```js
const a = [1];
Object.defineProperty(a, 0, { get() { throw 0; }, enumerable: true, configurable: true });
window.anyExposedApi.anyFunction(a);   // renderer aborts
```

or, without touching the array, `Object.defineProperty(Array.prototype, 0, {get(){throw 0;}})` then
pass `[,]`. DoS only — no cross-world reference leak was found, and a `TryCatch` would not help since
`ToLocalChecked` aborts on emptiness regardless of exception state. Secondary:
`size_t length = arr->Length();` is unbounded and implicitly narrowed into
`v8::Array::New(isolate, length)` (an `int` parameter).

#### C17. DevTools context menu UAF during a blocking macOS menu — MEDIUM

`shell/browser/ui/devtools_context_menu.cc:80` + `shell/browser/ui/inspectable_web_contents_view.cc:204`.
On macOS `MenuRunner::RunMenuAt` for a `CONTEXT_MENU` **blocks**, pumping the main run loop, and then
dereferences `this` (`menu_runner_`, `OnMenuClosed()`) after it returns. But the object is owned by
`InspectableWebContentsView::context_menu_`, and `CloseDevTools()` destroys it with
`context_menu_.reset()`. Any task pumped by the nested menu loop that closes DevTools frees the
`DevToolsContextMenu` whose `RunMenuAt` frame is still live. The code guards against `menu_runner_`
having been reset but **not** against `this` having been freed. Path: the frontend calls
`showContextMenuAtPoint`, then a queued task (its own `closeWindow()` → `CloseDevTools()` →
`context_menu_.reset()`, or an app-side `webContents.closeDevTools()`) runs inside the loop.
Electron's own comment states both the blocking behaviour and the teardown hazard.

#### C18. DevTools save-to-file writes to a stale path — MEDIUM

`shell/browser/api/electron_api_web_contents.cc:4538`. Two defects from one refactor
(`6f915e85e`, #47428):

1. `base::FindOrNull(saved_files_, url);` is called for effect and its **return value is
   discarded**, so `path` is always `nullptr` at the branch below.
2. `try_emplace` does not overwrite, so a second save of the same URL writes to the *previously*
   chosen file, not the one the user just picked.

The pre-refactor code was correct (find + assign, then `operator[]`, which overwrites). Rated MEDIUM
rather than LOW on the stronger analysis: the DevTools frontend controls both the `url` key and the
content blob, so one user approval to path P becomes a repeatable **silent overwrite** of P while the
user believes they saved to Q. Found independently by two agents. **Fix:**
`path = base::FindOrNull(...)` and `insert_or_assign`.

#### C19. Notification service stores a raw `RenderFrameHost*` — MEDIUM

`patches/chromium/notification_provenance.patch` gives `BlinkNotificationServiceImpl` a stored
`raw_ptr<RenderFrameHost> render_frame_host_`, passed to `DisplayNotification()` on every
`DisplayNonPersistentNotification` mojo call. Upstream **deliberately** does not store a raw
`RenderFrameHost*` here — the same constructor already receives a
`const WeakDocumentPtr& weak_document_ptr` precisely so the document can be re-resolved safely at
use time. `BlinkNotificationServiceImpl` is owned by `PlatformNotificationContextImpl::services_`,
not by the RFH, and the mojo pipe stays open until the **renderer** drops it — which a compromised
renderer simply declines to do. It can keep the pipe alive after its frame is detached and the
browser-side RFH destroyed, then call `DisplayNonPersistentNotification`; Electron dereferences
immediately at `shell/browser/electron_browser_client.cc:985-986`
(`content::WebContents::FromRenderFrameHost(rfh)`). Bare `raw_ptr`, no `DanglingUntriaged`
annotation, no observer to null it. Under BackupRefPtr this is a renderer-triggerable browser crash;
without BRP it is a genuine UAF. **Fix:** drop the member; use the `WeakDocumentPtr` already in the
constructor with `AsRenderFrameHostIfValid()`, or store a `GlobalRenderFrameHostId` and re-resolve.

#### C20. Guest-identity `CHECK_EQ` in `CreateNewWindow` commented out — MEDIUM

`patches/chromium/chore_partial_revert_of.patch`:

```diff
-  CHECK_EQ(source_site_instance->GetSecurityPrincipal().IsGuest(), is_guest);
+  // CHECK_EQ(source_site_instance->GetSecurityPrincipal().IsGuest(), is_guest);
```

in `WebContentsImpl::CreateNewWindow()`. The patch header admits the root cause is unknown: "some
pre-existing behavior in Electron is incompatible with this assertion. I will file an
upgrades-followup-task issue in Electron and try to track down the source of this problem." That is
an acknowledgement that the invariant is **violated**, not a mitigation. Renderer-initiated
`window.open()` from inside a `<webview>` is the reachable trigger; with the assertion off, a
divergence proceeds silently into the SiteInstance/StoragePartition selection immediately following,
so a guest-originated popup can land in a BrowsingInstance whose guest-ness (and
`StoragePartitionConfig`) does not match the opener's. **Compounding:**
`patches/chromium/chore_patch_out_partition_attribute_dcheck_for_webviews.patch` disables the other
half of the same invariant (`DCHECK(!partition_config.is_default())` in
`SiteInstanceImpl::CreateForGuest`). Neither side is enforced any more.

#### C21. Crashpad client PID spoofing check `#if 0`'d — MEDIUM (Windows)

`patches/chromium/crashpad_pid_check.patch` disables the anti-spoofing check that compares the
claimed client PID against `GetNamedPipeClientProcessId`. The header says "I don't understand why
Chromium does not have this issue." It dates from 2019, pending a `crashReporter` redesign that never
happened. The crashpad named pipe is intentionally reachable from sandboxed children, so a
compromised renderer (or any same-user local process) can register with a forged
`client_process_id`; the handler, running **unsandboxed** at the user's integrity level, then calls
`OpenProcess(kXPProcessAllAccess, ...)` on the forged PID. Practical exploitation is constrained —
dump-request events are duplicated into the impersonated process, not the attacker's — so the
concrete impact is that the crash handler holds `PROCESS_ALL_ACCESS` handles on arbitrary PIDs at a
renderer's request, and crash reports can be attributed to processes that did not produce them.
**Fix:** use the real PID from the API for `OpenProcess` and ignore the client-supplied value — that
resolves both the mismatch complaint and the spoofing primitive.

#### C22. `<webview>` fullscreen Escape loop never advances — MEDIUM (browser hang)

`patches/chromium/webview_fullscreen.patch`:

```cpp
while (auto* outer_web_contents = GetOuterWebContents()) {
  auto result = outer_web_contents->PreHandleKeyboardEvent(event);
  if (result == HANDLED) return HANDLED;
}
```

The loop variable never advances — `GetOuterWebContents()` is re-evaluated on `this` every iteration,
returning the same pointer forever. (The replaced upstream code did a single non-looping hop to
`GetOutermostWebContents()`.) A page inside a `<webview>` requests fullscreen and the user presses
Escape — the standard way to leave fullscreen. If no WebContents in the chain returns HANDLED, the
browser UI thread spins forever, re-emitting `before-input-event` on each pass; the app hangs and
must be force-quit. **Compounding:** termination depends on some ancestor returning HANDLED, which
for Escape depends on `FullscreenController::IsTabFullscreen()`, i.e. on `tab_fullscreen_` — and
`patches/chromium/fix_adapt_exclusive_access_for_electron_needs.patch` wraps the
`tab_fullscreen_ = true;` assignment in `EnterFullscreenModeInternal` inside `#if 0`, so
`tab_fullscreen_` is **never set**. Together, the two patches make the non-terminating path the
common case rather than an edge case.

#### C23. AI manager dereferences a null or stale RFH — MEDIUM

`d0c75f90a` "feat: implement the Prompt API via localAIHandler (#50659)".
`shell/browser/ai/proxying_ai_manager.cc:55-81`: `ElectronBrowserClient::BindAIManager` receives a
**nullable** `RenderFrameHost*` — the class comment says the manager is "Owned by the host of the
document / service worker", and the constructor itself handles null
(`rfh ? rfh->GetWeakDocumentPtr() : content::WeakDocumentPtr()`). But `GetAIManagerRemote()` guards
with only a `DCHECK`, then dereferences three times (at `:62-63` and `:74-75`). `DCHECK` compiles out
in release. It is also reached when `rfh_` has merely gone **stale**: `WeakDocumentPtr` invalidates on
document change, while the `ProxyingAIManager` is cached on `context_user_data` under a fixed key
`"ai_manager"` and reused for whatever document next binds through that host.

Trigger: web content in any context binding `blink::mojom::AIManager` without an associated RFH
(service or shared worker) calls `LanguageModel.availability()` → browser crash. Precondition: the
app called `session.registerLocalAIHandler()`; `enable_prompt_api = true` by default
(`buildflags/buildflags.gni:21`). **Secondary and arguably worse:** when the manager is reused for a
second document, the origin/frameToken/renderProcessId handed to the app's Prompt API handler
describe the **first** document — an app authorizing prompts per-origin authorizes the wrong one.

---

### Low-severity findings

| Finding | Location | Note |
|---|---|---|
| `corsEnabled` schemes are readable by every origin | `electron_api_protocol.cc:150`, `electron_url_loader_factory.cc:444` | Downgraded from HIGH: intentional, test-asserted at `spec/api-protocol-spec.ts:1111-1117`; a safe recipe exists (`{standard, secure, supportFetchAPI}` without `corsEnabled`); ACAO:`*` means credentialed reads still fail. Real issue is a misleading name with a one-line doc. |
| CORS not enforced for intercepted built-in schemes | `electron_url_loader_factory.cc:444`, `proxying_url_loader_factory.cc:846` | Same root cause; structurally supported in-tree but **unconfirmed** — whether `CorsURLLoaderFactory` sits below the appended proxy needs a Chromium checkout. If it holds, this is MEDIUM+: `protocol.handle('https', …)` + the documented `net.fetch(req, {bypassCustomProtocolHandlers:true})` fallback yields credentialed cross-origin reads. |
| `finishTransferSharedTexture` unvalidated mojo deserialize | `electron_api_shared_texture.cc:768-813` | Downgraded from HIGH: no privilege boundary crossed. Four real defects (discarded `ConvertFromV8` at `:771`, unchecked `As<v8::Object>()` at `:777`, unchecked `std::optional` at `:785`, raw `Serializer::Deserialize` with no `Validate()` at `:789`), but the only caller is `lib/renderer/api/shared-texture.ts:16` driven by browser-generated data, `subtle` reaches only preloads/nodeIntegration, and corruption stays in the attacker's own renderer. |
| Raw OS handles accepted from JS | `electron_api_shared_texture.cc:673,693-695,710` | `reinterpret_cast<HANDLE>`/`reinterpret_cast<IOSurfaceRef>`+`CFRetain`/`dup()` on JS-supplied integers. Same reachability limit as above. Validate `CFGetTypeID` / `GetHandleInformation`, or hand out table-indexed tokens. |
| `invokeInWebContents` accepts a reply from any frame | `lib/browser/ipc-main-internal-utils.ts:17-38` | Downgraded from MEDIUM: `ElectronApiIPC` is bound only for the primary main frame or under `nodeIntegrationInSubFrames` (`electron_browser_client.cc:1633-1647`), so the posited cross-site subframe has no binder. Defense-in-depth inconsistency vs. the sibling `invokeInWebFrameMain`. |
| `Wrappable::FromV8Impl` has no type tag check | `shell/common/gin_helper/wrappable.cc:207-215` | Downgraded from MEDIUM: blast radius is five classes (`View`→`ImageView`,`WebContentsView`; `BaseWindow`→`BrowserWindow`), not "every TrackableObject". Main-process only. The 2-arg overload at `:217-241` does check. |
| `postData` `bytes` null deref | `shell/common/gin_converters/net_converter.cc:663` | `dict.Find("bytes")` dereferenced blind while `type` and `file` three lines either side are null-checked. Crash-on-bad-input in a main-process API. |
| `LoginHandler` binds a raw `WebContents*` into a PostTask | `login_handler.h:23`, `login_handler.cc:39-44,64-80` | Downgraded: `WebRequest::OnRequestWillBeDestroyed` (`electron_api_web_request.cc:667-669`) does erase the handler, and the exposure is a single UI-thread task hop, not an indefinitely held pointer. Still: bind `GetWeakPtr()`. |
| Cookie domain filter direction inverted | `electron_api_cookies.cc:119`, `docs/api/cookies.md:81-82` | `74c4ae0b5` swapped `MatchesDomain` for `cookie.IsDomainMatch` — opposite containment direction, hand-traced and confirmed. `cookies.get({domain:'example.com'})` now misses host-only subdomain cookies (a "log out everywhere" flow silently leaves auth cookies behind). Docs still describe the old direction; no breaking-change entry; the regressed case has no test. |
| webRequest listener registered after a pattern parse error | `electron_api_web_request.cc:722-723,746` | `AddUrlPatterns` is `void`; `ThrowTypeError` only sets a pending exception and control flow continues to `:746`. Combined with the same commit flipping empty-set semantics to "match nothing", a filter whose first pattern fails matches nothing. Needs a malformed pattern **and** an app that swallows the TypeError. The `filter_types` loop at `:725-733` gets it right. |
| CODEOWNERS infra sign-off removed | `.github/CODEOWNERS` | See [A2](#a2-codeowners-infra-sign-off-removed--low-downgraded-from-medium). |
| Homebrew pinning/notarization removed | `pipeline-segment-electron-publish.yml:159` | See [A3](#a3-homebrew-pinning-and-notarization-check-removed-from-the-macos-release-path--low). |
| Untrusted input back into a `run:` block | commit `d430d00f0` | See [A4](#a4-untrusted-input-moved-back-into-a-run-block--low). |
| `sendToFrame` uses a global frame lookup | `lib/browser/api/web-contents.ts:137` | `[processId, frameId]` ignores the `contents` arg — a global `RenderFrameHost::FromID`, so a message can land in a frame owned by a different WebContents/session. |
| `loadFile` not confined to the app root | `lib/browser/api/web-contents.ts:349` | Documented as "relative to the root of your application" with no containment check; `path.resolve` returns an absolute `filePath` verbatim and normalizes `../` upward. |
| `OnViewAddedToWidget` unchecked WeakPtr | `electron_api_web_contents_view.cc:115` | Every sibling method null-checks; this one does not. |
| FilePath converter returns true without writing | `file_path_converter.h:22-31`; misuse at `electron_api_shell.cc:131-149` | JS `null` returns `true` without writing `*out`, so `WriteShortcutLink` reusing one `FilePath` makes `{target:'…cmd.exe', cwd:null}` set the working dir to the target exe. `image_converter.cc:28-29` has the identical shape. |
| Skia `AddImageRep` unvalidated dimensions | `skia_util.cc:107-133` | Guards `== 0` instead of `<= 0`, so negative dims reach `SkImageInfo::MakeN32`; the `writePixels()` bool is discarded, publishing an `SkBitmap` over uninitialized heap. Sibling at `electron_api_native_image.cc:509-519` gets it right. |
| `NODE_EXTRA_CA_CERTS` not stripped in packaged apps | `node_bindings.cc:495-500` | Stripped only when the `nodeOptions` fuse is off, never subjected to the packaged-app allowlist that follows. Local attacker gets silent TLS MITM of update manifests/telemetry in Node's stack. |
| asar `unpacked` files outside integrity coverage | `archive.cc:101-106`, `:369-372` | `FillFileInfoWithNode()` returns early for `unpacked` entries **before** the integrity block, so `.node` addons under `app.asar.unpacked/` load unvalidated with `embeddedAsarIntegrityValidation` on. Mitigating: the *set* of unpacked entries is header-protected. |
| DevTools `showItemInFolder` parent traversal | `inspectable_web_contents.cc:790` | The workspace-root allowlist uses `FilePath::IsParent`, which is purely lexical; `ReferencesParent()` is never rejected. Defeats a control the code documents as a security boundary (`b4e14a900`, #50905). No content returned. |
| DevTools save-to-file unsanitized default path | `electron_api_web_contents.cc:4552` | Frontend-supplied `url` becomes the dialog `default_path` via `FromUTF8Unsafe` and the title, with no sanitization, length cap, or download-dir anchor. Chromium's `DevToolsFileHelper::Save` does all three. |
| asar integrity validated after delivery (TOCTOU) | `asar_url_loader.cc:181,279`, `asar_file_validator.cc:71` | Hashes are only compared per `block_size` (4 MiB default) or in `OnDone()`, but `Start` hands the data-pipe consumer to the renderer first — so any entry smaller than a block (essentially every JS/HTML file) is fully delivered before its hash is checked. The later `LOG(FATAL)` does not retract read bytes. Non-streaming paths get the ordering right. |
| asar `link` cycle unbounded recursion | `archive.cc:288` | `GetFileInfo` follows `link` by calling itself with no cycle detection or depth limit; `{"files":{"a":{"link":"a"}}}` exhausts the stack. `Archive::Init` does no structural header validation beyond JSON parsing. |
| asar unvalidated size and header length | `archive.cc:95,219,265` | `"size"` read as signed and cast to `uint32_t`; header length used unbounded in `buf.resize`; `header_size_ = 8 + size` in 32-bit arithmetic with no `CheckedNumeric`. Realistic outcome is OOM, since every consumer reads through `base::File::ReadAndCheck`. |
| Renderer init URI decode aborts preload and page load | `lib/renderer/init.ts:92`, `lib/worker/init.ts:29` | Untried `decodeURIComponent` on `location.pathname`; `file:///%C0%80.html` throws `URIError` before preloads load and before `appCodeLoaded()`, so **no preload runs** and `SetDefersLoading(kStrict)` is never lifted. |
| `gin::DeprecatedWrapperInfo::From()` missing null check | `chore_restore_some_deprecated_wrapper_utility_in_gin.patch` | The same patch makes new-style `gin::Wrappable` pass the field-count guard and yield `info == nullptr`; `internal::FromV8Impl` checks `!info` but only **after** `From()` dereferenced. One-line fix. 16 deprecated + 47 new-style types coexist. |
| Node secure heap silently downgraded under the V8 sandbox | `patches/node/support_v8_sandboxed_pointers.patch` | Upstream fails closed with `UNREACHABLE()`; the patch substitutes a plain `ArrayBuffer::New` — swappable, non-cleansed V8 heap memory returned as if it were secure-heap memory. The neighbouring `ByteSource::ReleaseToBackingStore` change in the *same patch* preserves zero-on-free, so this reads as an oversight. |
| Windows toast presenter cross-thread UAF | `windows_toast_notification.cc:250,265,331-333` | `90e338df5` moved toast creation to a `CONTINUE_ON_SHUTDOWN` thread-pool sequence capturing `NotificationPresenter*` as a bare raw pointer (only the `Notification` gets weak-pointer protection), then dereferences it for `SaveIconToFilesystem`. |
| `net` module silently auto-selects a client certificate | `electron_api_app.cc:790-798` | `e852c260a` routed `net.request`/`net.fetch` cert requests into `App::SelectClientCertificate`, which auto-selects the first matching platform cert when no listener exists. A path that previously could never disclose a client cert now can, silently. Documented with an opt-out. Bonus pre-existing bug: `(*shared_identities)[0]` indexes an empty vector when there are no matches. |
| `WebContents::Clone` lossy preference snapshot | commit `76a03e101` | Rebuilds prefs from `GetLastWebPreferences()`, a 13-key snapshot. `disableBlinkFeatures` is **lost** while `enableBlinkFeatures` is preserved — the asymmetry only ever loosens. Any future security pref not added to `SaveLastPreferences()` silently will not be inherited. |
| Clipboard sync handler missing `event.type` guard | `lib/browser/rpc-server.ts:43-49` | The only handler in the file without an `event.type !== 'frame'` guard; a compromised service-worker renderer reaches full clipboard read/write on Linux (the allowlist is all of `Object.keys(clipboard)`). |
| Linux xdg argv missing `--` | `platform_util_linux.cc:358,421-433` | No end-of-options separator before caller-supplied paths in `xdg-open`/`gio`/`kioclient`/`trash-put`. A relative path named `--empty` turns `shell.trashItem` into `gio trash --empty`. `execvp`, so option injection, not command injection. |
| utilityProcess stdio uninitialized + OOB read | `electron_api_utility_process.cc:576` | `IOType type;` uninitialized with no terminal `else`; `stdio_arr[i]` indexed for `i` in `[0,3)` after `opts.Get` may have installed a shorter vector. JS wrapper validates, so reachable only via the raw binding. |
| Unbounded crash-key annotation growth | `crash_keys.cc:34-71` | No cap on the *number* of distinct crash keys; each appends a `CrashKeyString<20320>` to a never-shrinking deque. `addExtraParameter` is exported to renderers; ~100k keys ≈ 2 GB. |
| `net.request` redirects into custom schemes | `electron_api_url_loader.cc:811` | `IsSafeRedirectTarget` blocks only `about`/`file`/`filesystem`/`blob`/`data` + WebUI; app-registered custom schemes are not covered and `bypassCustomProtocolHandlers` defaults to false. |
| FSA restricted-path callback dropped when no listener | `file_system_access_permission_context.cc` | Fails **closed**, but the callback is never run and the `callback_map_` entry never extracted, so the FSA promise never settles and every later request for that path queues behind it forever. |
| FSA `PermissionGrantImpl::GetStatus` unchecked WeakPtr | `file_system_access_permission_context.cc` | Dereferences `context_` with no null check while the sibling `RequestPermission()` at `:305` does. |
| Serial ephemeral grants never dropped on port loss | `serial_chooser_context.cc` | The `ephemeral_ports_` erase loop sits in `OnPortAdded()` where it is a no-op; `OnPortRemoved()` erases only `port_info_`. HID and USB both clear ephemeral state on removal — serial is the outlier. |
| Ephemeral device grants bypass the device permission handler | `serial`/`hid`/`usb` chooser contexts | All three `Has*Permission` return true from the ephemeral map **before** reaching `CheckDevicePermission`, so a `setDevicePermissionHandler` returning false cannot deny a device lacking a stable id. |
| Badge set without origin scoping | `BadgeManager::SetBadge`/`ClearBadge` | Applies to the whole app via `Browser::Get()->SetBadgeCount()` without consulting the `BindingContext` that was deliberately captured — `receivers_.current_context()` is never called anywhere in the file. Any cross-origin iframe or service worker can spoof the unread count. |

### Informational observations

Recorded as defects without a demonstrated attacker path, or as latent gadgets:

- **`_printToPDF` unchecked derefs** (`electron_api_web_contents.cc:3651`) — traced and cleared for
  the public API; the JS wrapper always supplies `?? ''` defaults.
- **Context-bridge recursion-depth reset** (`electron_api_context_bridge.cc:689,698` pass literal
  `1` instead of `recursion_depth + 1`) — unreachable in a shipping build;
  `support_dynamic_properties` is only true via `internalContextBridge`, attached only under
  `#if DCHECK_IS_ON()`.
- **DevTools custom menu action id not range-checked** (`devtools_context_menu.cc:105`) — requires a
  compromised renderer; Blink bounds the id at `kMaxContextMenuAction = 1000` for ordinary JS.
- **`kBypassCustomProtocolHandlers` read from a renderer-writable options bitfield**
  (`proxying_url_loader_factory.cc:847`) — not reachable from web content; a compromised renderer
  could skip the app's `protocol.handle` policy.
- **`IsRedirectSafe()` deliberately dropped** (`proxying_url_loader_factory.cc:289`, with an
  in-code comment saying so) — no web-content-reachable path found.
- **`--inspect` not checked in the `ELECTRON_RUN_AS_NODE` entry** (`node_main.cc:66-88,281-286`) —
  grants nothing extra, since reaching `NodeMain()` already gives `-e` code execution.
- **`<webview>` prototype methods accept a forged `this`** (`lib/renderer/web-view/web-view-impl.ts:211-246`)
  — bounded by the browser's `getGuestForWebContents` "Access denied" check and the Set-based method
  allowlists.
- **`webFrame` method forwarder has no allowlist** (`lib/renderer/web-frame-init.ts:13-21`) — the
  `keyof` type claim in the comment is erased at runtime; no attacker path today (three senders, all
  literal), but a latent gadget.
- **`ToLocalChecked()` on element `Get`** in `std_converter.h:153,173,179,186`,
  `net_converter.cc:226,235,240`, `net_converter.h:163`, `electron_api_v8_util.cc:35,37`,
  `electron_api_shared_texture.cc:630` — a throwing Proxy trap turns a JS exception into a fatal
  CHECK. The same files get it right at `std_converter.h:176` and `net_converter.cc:283`.
- **Blob holder not session-scoped** (`electron_api_data_pipe_holder.cc:32`) — process-global
  monotonic ids, global map, no session check in `Session::GetBlobData`.
- **`enableWebSQL` inheritance is dead code** (`guest-view-manager.ts:60`) — shows the inheritance
  table and the C++ serialization can drift apart unnoticed.
- **`parseWebViewWebPreferences` applies no allowlist** (`parse-features-string.ts:83-85`) — traced
  to a negative result; forced `sandbox: true` short-circuits `IsSandboxed()`.
- **`shell.openExternal` has no scheme allowlist** — argument *splitting* is prevented on Windows,
  but the scheme is unconstrained. Same sink as [C1](#c1-external-protocol-navigation-grants-by-default--medium-downgraded-from-high-report-with-the-permission-fail-open), different route.
- **Residual `run:` interpolations** — see [A5](#a5-residual-run-block-interpolations--info).
- `menu.sendAction` arbitrary selector; `desktopCapturer` thumbnail size unclamped.

---

## Corrected and withdrawn

This section records what the review got wrong. It is not a formality — one finding was reported to
the requester as confirmed before it was refuted, and several severities were inflated.

### Withdrawn entirely

**Bluetooth first-device auto-selection (originally HIGH) — RETRACTED.**

The finding claimed that `shell/browser/lib/bluetooth_chooser.cc:110-118` auto-selects the first
discovered Bluetooth device when no app listener is registered, because
`EventEmitterMixin::Emit` returns `GetDefaultPrevented()`, which is false when nothing is listening
— and that `docs/api/web-contents.md:884` ("If no event listener is added for this event, all
bluetooth requests will be cancelled") is therefore **false**.

**This is wrong, and the docs are correct.** The finder read only the C++ and missed the JavaScript
layer. `lib/browser/api/web-contents.ts:857-863`, inside `WebContents.prototype._init` — installed on
**every** WebContents at construction — registers an internal listener:

```ts
this.on('select-bluetooth-device', (event, devices, callback) => {
  if (this.listenerCount('select-bluetooth-device') === 1) {
    // Cancel it if there are no handlers
    event.preventDefault();
    callback('');
  }
});
```

With no app listener, `listenerCount === 1` (the internal one), so `preventDefault()` runs,
`Emit` returns `true` (it returns `event->GetDefaultPrevented()`, `event_emitter_mixin.h:40`), the
`if (!prevent_default)` auto-select at `bluetooth_chooser.cc:117` is **skipped**, and `callback('')`
→ `OnDeviceChosen("")` → `event_handler_.Run(CANCELLED)`.

**Bluetooth fails closed.** Docs lines 884 and 886 are consistent, not contradictory: 884 describes
the no-listener case handled by the internal listener; 886 describes the app-listener case where the
internal branch is skipped and the C++ auto-selects. The "Bluetooth is the sole outlier versus
HID/serial/USB" framing also collapses — Bluetooth reaches the same fail-closed outcome, one layer up.

*(The separate Bluetooth finding — [C7](#c7-bluetooth-service-allowlist-is-a-notimplemented-stub--medium),
the `NOTIMPLEMENTED()` service allowlist — is unaffected and stands at MEDIUM. But its original
framing, "combined with the auto-selection bug, untrusted content gets unrestricted GATT access
behind any click", must be dropped: it requires the page to already hold a device, which now needs an
app that actually approves one.)*

### Severity downgrades

| Finding | From → To | Reason |
|---|---|---|
| Preload code-cache poisoning | CRITICAL → **HIGH** | No JavaScript surface exists for the mojo call; `preload_utils::CreatePreloadScript` is the only in-tree caller and it computes the hash itself. A prior renderer compromise (native code execution) is required. Three agents rated it CRITICAL, HIGH and MEDIUM respectively; HIGH is the correct calibration — the precondition is real, and so is the escalation to persistent, restart-surviving, fuse-bypassing preload-privilege code execution. |
| Fork-PR CI code execution | CRITICAL, **contingent** | Confirmed and in fact under-stated by refutation. But the effective mitigation is a GitHub setting not stored in-tree; under the stricter fork-approval setting the code-execution half is MEDIUM. The cache-integrity gap is unconditional. |
| `<webview>` embedder frame token | HIGH → **MEDIUM** | Process pinning is a real mitigation the finder underweighted: `embedder_process_id` comes from the trusted `event.sender`, so the token can only resolve to a frame in the embedder's own process. Cross-WebContents attach needs a second WebContents already sharing that process. Also **not a regression** — the `DCHECK` has been there since 2018. |
| WebUI factory scheme check | HIGH → **MEDIUM** (may fall to INFO) | The defect is confirmed and Chrome's factory verbatim performs the check Electron omits. But the decisive step — whether content grants WebUI bindings to a frame committing `http://` — is unresolved, and the attacker must control a host literally named `accessibility`, which arbitrary remote web content cannot arrange. |
| External-protocol navigation | HIGH → **MEDIUM** | The "sandbox-flags gate is skipped for main frames" hole is upstream-faithful — Chrome does the same, and the code comment says so. And this is Electron's documented fail-open permission model, not an independent bug; it should be reported together with the permission-manager default. |
| `corsEnabled` scheme exposure | HIGH → **LOW** | Intentional and pinned by Electron's own test, which the hardening commit `92f0993d9` deliberately added. A safe recipe exists (drop `corsEnabled`), and the hard-coded `ACAO: *` means credentialed cross-origin reads still fail. The real problem is a misleading API name with a one-line doc. |
| `finishTransferSharedTexture` | HIGH → **LOW** | All four defects exist verbatim, but no privilege boundary is crossed: the only caller carries browser-generated data, `subtle` reaches only preloads and `nodeIntegration` contexts, and the GPU interface is the renderer's own. The finder called the bytes "attacker-controlled" without establishing who the attacker is. |
| IPC emitter array escalation | MEDIUM-HIGH → **MEDIUM** | The escalation was unearned. Only the *emitter* is aliased; `event.sender`/`event.senderFrame` stay truthful, so any app that validates the sender is unaffected. Window-2 added provenance, not reachability. |
| `invokeInWebContents` frame confusion | MEDIUM → **LOW** | The posited attacker cannot reach the reply channel: `ElectronApiIPC` is bound only for the primary main frame or under `nodeIntegrationInSubFrames`, a configuration that already grants Node/RCE in that frame. *(Note the asymmetry: this same binder gate does **not** apply to `ElectronWebContentsUtility`, which is exactly why the preload-cache finding's cross-origin-OOPIF reachability survives where this one's does not.)* |
| `Wrappable::FromV8Impl` type check | MEDIUM → **LOW** | "Every TrackableObject/EventEmitter is mutually interchangeable" is wrong at HEAD. A grep for the three base-class patterns returns four hits — a five-class hierarchy. Everything else migrated to `DeprecatedWrappable` (which uses the 2-arg overload *with* the check) or to cppgc `gin::Wrappable`. |
| `postData` bytes null deref | MEDIUM → **LOW** | Crash-on-bad-input in a main-process API, not an attacker primitive. |
| Cookie domain filter inversion | MEDIUM → **LOW** | Confirmed by hand-tracing both algorithms, but it is a filter-only read API in the main process with no attacker-controlled input and no memory-safety consequence. It is a docs/breaking-change omission. |
| webRequest filter fail-open | MEDIUM → **LOW** | Reaching the fail-open state needs two app-side conditions: a malformed pattern **and** a `try/catch` that swallows the TypeError. Without the catch, the app sees a hard error at setup. |
| `LoginHandler` dangling pointer | MEDIUM → **LOW** | The finder missed a cleanup path (`WebRequest::OnRequestWillBeDestroyed` at `electron_api_web_request.cc:667-669` erases the handler, and WebContents destruction cancels its in-flight requests, which fires it) and over-stated the window: the PostTask is issued in the constructor and runs exactly once. "UAF a renderer can influence via heap grooming" is not supported. |
| FSA revocation dead code | MEDIUM → **LOW-MEDIUM** | The dead code is confirmed exhaustively, but the consequence is Electron's pre-existing behaviour. This is a hardening that never activated, not an introduced regression. |
| CODEOWNERS removal | MEDIUM → **LOW** | CODEOWNERS is advisory unless a ruleset enables "Require review from Code Owners", and no such artifact exists under `.github/`. The "stealth commit" framing was unsupported and is withdrawn: the change went through a numbered, reviewed PR from a long-standing maintainer, and empty commit bodies are this repo's norm. |
| Residual `run:` interpolations | LOW → **INFO** | Inert for two independent reasons; the finder undersold its own case by naming only one (the login charset — the heredoc is single-quoted, so no expansion occurs at all). |

---

## Verified clean

These negatives cost as much work as the findings and are worth as much.

### The fix-regression check found nothing

**No security guard that Electron previously landed has been reverted, refactored away, or bypassed
at HEAD.** Numbers: 333 candidate fix commits identified, 199 after excluding noise; **38 guards
traced end-to-end** (commit diff → identify guard → pickaxe for add/delete → read the file at HEAD);
plus 22 context-bridge guards and 16 asar guards verified by dedicated sub-agents covering 84 and
255 commits respectively. An automated erosion scan over all 177 filtered candidates extracted every
guard-shaped added line and checked its presence at HEAD: 37 absent, **all 37 triaged to benign
refactors** (helper renames, `getWebPreference()` removal, warning-text changes, `nativeWindowOpen`
deletion).

Guards verified intact — selection: the `ElectronApiIPC` main-frame-or-`nodeIntegrationInSubFrames`
binding gate (`e07c2b84d`); `isWebViewTagEnabled` + `makeSafeHandler`; `getGuestForWebContents`
"Access denied"; the `syncMethods`/`asyncMethods`/`properties` allowlists; `preload` removed from
`allowedWebPreferences` (`375b79398`); webview security-pref inheritance applied **after** the
renderer-controlled spread; `CheckCommandLineArguments` for CVE-2018-1000006 (`c49cb29dd` — one call
site originally, one at HEAD, no erosion); `NODE_OPTIONS` parent-process stripping; all fuse gates;
asar integrity header + block hashes with `LOG(FATAL)`; `EscapeExternalHandlerValue` before
`ShellExecuteEx`; `NormalizePathSeparators`; the sandboxed-iframe external-protocol escape-token
check; `nodeIntegrationInWorker` service/shared-worker rejection; the GHSA-h9jc-284h-533g
context-bridge proxy-dict-in-destination-scope fix; default_app hardening.

**Several guards were strengthened**, not merely preserved: the macOS parent code-signature check
moved from a raw `getppid()` to `audit_token_t` (closing PID reuse); `nodeIntegrationInWorker`
rejection extended to worklets; default_app moved to `contextIsolation: true`, `sandbox: true`,
`nodeIntegration: false`; `IsValidWrappable` tightened from "any gin wrappable passes" to an exact
`info != wrapper_info` comparison and extended to `UtilityProcessWrapper::PostMessage`, which
previously had none.

**Revert audit:** 673 commits mentioning revert, 254 after excluding version bumps, 71 touching
security paths. Every security-relevant revert resolves to "the guarded code path no longer exists"
or "superseded by a stronger mechanism". The two that looked worst are both moot: `6b41d8603`
reverted better window-hierarchy checks, but the entire custom `window.open` proxy
(`canAccessWindow`/`isScriptableWindow`/`isChildWindow`) was later deleted by `d44a187d0` — zero
occurrences at HEAD, with Blink and `ChildProcessSecurityPolicy` now enforcing the equivalent (and
no Electron patch weakens CPSP). `d27ad0d18` reverted "refactor: mmap asar files" along with a
`CheckedNumeric` bounds check, but that check existed only for mmap pointer arithmetic and the
reverted-to path uses the bounds-safe `base::File::ReadAndCheck`.

**No security regression test is disabled.** The `xit`/`xdescribe` entries in `spec/webview-spec.ts`
and `spec/api-protocol-spec.ts` are functional (visibilityState, getUserMedia, capturePage,
setDevToolsWebContents, POST); the context-bridge prototype-leak and asar-integrity tamper specs are
live.

### Supply-chain tamper sweep: clean on every axis

1. **Action pinning.** 300 unique `uses:` lines added across two years; **zero** used a mutable ref.
   No action was ever un-pinned. At HEAD, 61 unique refs (30 local, 31 external) — every external ref
   carries a 40-hex SHA.
2. **One-off contributors.** 9 authors with exactly one commit to sensitive paths, 8 more with 2-5;
   every diff read, nothing anomalous. Restricted to `.github/workflows` + `.github/actions`, the
   full contributor list is 19 names, **all** recognizable maintainers or bots. No unknown identity
   ever touched a workflow.
3. **Message/diff mismatch.** ~60 commits bucketed; the mismatched ones read. Two substantive hits,
   both reported above ([A2](#a2-codeowners-infra-sign-off-removed--low-downgraded-from-medium),
   [A3](#a3-homebrew-pinning-and-notarization-check-removed-from-the-macos-release-path--low)).
4. **Obfuscated blobs.** 4 hits, all benign; the one remote PowerShell bootstrap (chocolatey) is no
   longer present at HEAD.
5. **Network fetches.** All hosts reviewed. The `raw.githubusercontent.com` moves point at GitHub's
   official `chromium/chromium` and `nodejs/node` mirrors and are interpolation-safe — the
   `chromium_revision` is validated against `^[a-zA-Z0-9._-]+$`, and that guard was confirmed to
   survive the later `638fa338d` refactor.
6. **Committed credentials.** Zero matches for `ghp_|github_pat_|AKIA|PRIVATE KEY|npm_|xox[baprs]-`
   across all of `script/`, `.github/`, `build/` over two years.
7. **Committer anomalies.** None; every `.github/` and `script/` commit has GitHub as committer with
   a matching or bot author.
8. **Triggers.** No weakening. No workflow declares `workflow_run` anywhere. All **six**
   `pull_request_target` workflows carry `permissions: {}` and an explicit security banner; five
   perform no checkout at all, and `pr-template-check.yml:22-26` checks out with no `ref:` (so the
   base SHA), sparse-checkouts one markdown file, and executes no repository code.
9. **Permissions.** 47 workflow files, **47** with a top-level `permissions:` key, zero missing;
   45-46 are `permissions: {}` and the single exception is `scorecards.yml:11 read-all`.
   `packages: write` was never added; net direction is tightening.
10. **Dependencies — net hardening.** Both git-URL dependencies were removed, including
    `dbus-native` pinned to a **mutable branch ref** (`github:nornagon/dbus-native#master`) present
    since 2019, removed 2026-05-05. No pinned version loosened, no lifecycle script added.
    `537fd7b10` (yarn v4) introduced `enableScripts: false` + `npmMinimalAgeGate: 10080` (7-day
    quarantine) + `npmPreapprovedPackages` in one shot; `yarnPath` is a vendored `4.12.0.cjs`. Root
    `package.json` has no `postinstall` (it has a deliberate no-op `preinstall` and `prepare: husky`).
    In `DEPS`, all seven entries resolve to a full 40-hex commit or an exact version; a pickaxe over
    all 205 `DEPS` commits found no added branch/tag/HEAD refs, and only two hosts appear.
11. **Release pipeline — net hardening.** `dec7f937a` added `actions/attest-build-provenance` +
    `attestations: write` across all four publish workflows; `52929c93d`/`d9170093a` made upload
    failures fatal instead of silent; `22f15ec47` moved the token exchange onto Actions OIDC.

### Context bridge: the historical CVE fixes hold

All 1,175 lines read twice, and 22 guards re-verified by the regression agent:

- The `kOriginalFunctionPrivateKey` round-trip shortcut still enforces
  `GetCreationContextChecked(...) == destination_context` (`:213-217`) — the historical cross-world
  original-function leak stays fixed.
- `ProxyFunctionWrapper` never uses `info.This()`; it binds the receiver captured at proxy-creation
  time via `kProxyFunctionReceiverPrivateKey` (the `fd2861117` fix) — no `this` leak.
- The `__proto__` fix from `abffba454` is present and correct: `CreateDataProperty` performs
  `[[DefineOwnProperty]]`, which cannot trigger the inherited `__proto__` setter; the accessor branch
  uses `DefineProperty` for the same reason.
- `ObjectCache` is keyed by `v8::Local<v8::Object>` **identity**, with `GetIdentityHash` only as the
  hash and collisions resolved by pointer equality. Every `existing_object_cache` call site was
  traced: a single cache is never shared across both conversion directions.
- Promise proxying creates the resolver under `destination_scope`; reaction callbacks run in the
  destination realm.
- `IsPlainObject` excludes Proxy, so hostile proxies fall through to the structured serializer and
  throw. Symbols and BigInts pass as realm-free primitives. `DeepFreeze` failure is fail-closed.

### Fuse callsite map: exactly one fuse is bypassable

All 10 fuses were mapped to every callsite. Bypasses exist in **one** fuse only —
`embedded_asar_integrity_validation`, via [B3](#b3-asar-integrity-validation-skipped-in-macos-helper-processes--high)
(macOS helpers) and the `unpacked`-entries gap. Every other fuse: no bypass path found.

- `run_as_node` — clean. All four platform `main()`s check the fuse **and** `IsEnvSet(kRunAsNode)`
  before `NodeMain()`; `electron_library_main.mm:44` re-checks. Past fixes intact: the parent
  signature check via audit token (`node_main.cc:138-157`, from #50907) and `UnsetHijackableEnvs`
  (`node_main.cc:92-105`, from #41079).
- `only_load_app_from_asar` — clean. When set, `getOrCreateArchive(packagePath)` must succeed before
  `Module._load`, so an `app/` directory or `default_app.asar` cannot substitute. default_app's
  `--require`/`--app=` parsing is reachable only when this fuse is off.
- `grant_file_protocol_extra_privileges` — clean. `PreSandboxStartup()` appends
  `kAllowFileAccessFromFiles` unconditionally (`electron_main_delegate.cc:318`), but
  `OverrideWebPreferences()` runs later and overwrites `allow_file_access_from_file_urls` with the
  fuse value (`electron_browser_client.cc:453`), so the fuse wins. Renderer-side registration is
  duplicated (`renderer_client_base.cc:293`), so a renderer cannot obtain the privileges by omitting
  a browser-supplied switch.
- `node_cli_inspect` — allowlist-deny default, so underscore aliases (`--inspect_brk`) are dropped,
  not passed.
- `cookie_encryption`, `wasm_trap_handlers`, `load_browser_process_specific_v8_snapshot`,
  `node_options` — clean.
- The `--set-fuse-<name>=0|1` command-line override is guarded by `#if DCHECK_IS_ON()`.
  `build/args/release.gn` sets `is_official_build=true` and does not set `dcheck_always_on`, so
  release binaries have no override; `build/args/testing.gn` sets it, which is what
  `spec/fuses-spec.ts` relies on. Correct.

### asar path traversal: explicitly checked, not vulnerable

- Traversal via `../`, `%2e%2e`, `%2f`, `%00` and backslashes: **not vulnerable**.
  `net::FileURLToFilePath` rejects `%2F`, `%00` and (Windows) `%5C` outright, and GURL canonicalizes
  real and `%2e`-encoded dot segments before `GetAsarArchivePath` ever sees the path. Verified against
  upstream `net/base/filename_util.cc`.
- asar `link` entries resolve **only** inside the header dictionary, never onto the filesystem.
- `GetAsarArchivePath` uses `AppendRelativePath`, which cannot produce an absolute tail.
- `AsarURLLoader` range arithmetic (`first_byte_to_send`, `write_size`, `bytes_to_drop`,
  `start_block`) is bounded by `HttpByteRange::ComputeBounds(info.size)` and the
  `total_bytes_to_send == 0` early return — none of the subtractions underflow on a reachable path.
- `AsarFileValidator`'s `blocks[current_block_]` index is guarded by the `current_block_ > max_block_`
  FATAL and by `load_integrity = header_validated_`.
- `ToResponseHead` validates header names and values with `net::HttpUtil::IsValidHeaderName`/
  `IsValidHeaderValue` before `AddHeader` — **no CRLF injection**. `net::GetHttpReasonPhrase` returns
  a default for unknown status codes, so a hostile `statusCode` is not a browser-process CHECK.
- `ScopedTemporaryFile` uses `base::CreateTemporaryFile` (unpredictable name) and validates integrity
  before writing.

### Other verified-clean results

**Renderer main-world exposure inventory.** Under the default hardened configuration
(`contextIsolation: true`, `webviewTag: false`), **nothing** from the renderer subsystem reaches
`window` except `window.prompt` (a throwing stub), `window.close` (an IPC stub, only when
`!sandboxed && !isWebView`), the `document.hidden`/`visibilityState` getters inside a webview guest,
and whatever the app's own preload exposes. `ipcNative`, `guestViewInternal`, `Buffer` (sandboxed
pre-init), `emit-process-event`, `isWebView` and `native-binding-cache` are `v8::Private` hidden
values, never JS-reachable in any configuration. `internalContextBridge` — which can overwrite
arbitrary main-world globals — is attached only in DCHECK builds.

**The ESM preload change does not open a capture window.** Under
`contextIsolation: false` + `sandbox: false` + `nodeIntegration: false`, `process`/`Buffer`/
`setImmediate`/`clearImmediate`/`global`/`root`/`GLOBAL` are deleted in `onPreloadsLoaded`, which runs
**before** `appCodeLoaded()` lifts `SetDefersLoading(kStrict)`. The async `.finally(onPreloadsLoaded)`
path introduced by `29cd2d565` does **not** let page script capture `process` — the document body is
frozen until the promise settles. Confirmed against `spec/api-browser-window-spec.ts:4294-4308`.

**Sandboxed preload `require` is a closed allowlist.** `lib/sandboxed_renderer/preload.ts:56-66`
consults two Maps and otherwise throws — no path loading. `Map.prototype.has`/`get` are
pollution-proof, and `lib/common/define-properties.ts:9-16` installs the electron sub-modules as
**non-configurable** accessors, so one preload cannot swap out `electron.ipcRenderer` for another.

**`setWindowOpenHandler` cannot be used by a renderer to escalate `webPreferences`.**
`parse-features-string.ts:87-148` restricts renderer-settable prefs to
`{zoomFactor, nodeIntegration, javascript, contextIsolation, webviewTag}` and strips `webPreferences`
from top-level options entirely; `makeWebPreferences` (`guest-window-manager.ts:160-189`) applies
`securityWebPreferencesFromParent` **over** them. `preload`, `sandbox`, `webSecurity` and `partition`
are not renderer-reachable at all.

**`ElectronApiIPC` receivers cannot be used for frame spoofing.** `ElectronApiIPCHandlerImpl`
captures `render_frame_host_id_` at **bind** time from the real requesting frame, one receiver per
frame; `frameId`/`processId`/`senderFrame`/`frameTreeNodeId` all derive from it, never from the
payload.

**`v8_util.cc` serialization.** No memory-safety defect found. `ReadNativeImage` checks every
`ReadUint32`/`ReadDouble`/`ReadRawBytes` return before use, delegates bitmap parsing to
`skia::mojom::InlineBitmap::Deserialize` (a **validating** mojo deserializer, unlike the
shared-texture path) and checks its result, and `ReadBlinkEnvelope` validates both the version tag
and the trailer tag. *(One residual: the `double scale` passed to `gfx::ImageSkiaRep` — including
0.0, negative and NaN — was flagged by one agent and found unremarkable by another. Unresolved
without a Chromium checkout; see [Coverage and limits](#coverage-and-limits).)*

**Historical Windows/platform fixes intact.** `platform_util_win.cc:246` wraps the URL in literal
quotes **and** runs `EscapeExternalHandlerValue` (CVE-2018-1000006 class). `Browser::IsValidProtocolScheme`
(`browser.cc:78`) enforces RFC-3986 scheme syntax and `electron::AddQuoteForArg` implements correct
`CommandLineToArgvW` quoting. Windows toast markup cannot be injected — `XmlWriter` escapes, verified
against Chromium's `third_party/libxml/chromium/xml_writer.cc`. The `requestSingleInstanceLock`
`additionalData` path bounds-checks `num_args` and `additional_data_size`, and `V8Deserializer`
checks the envelope tag, `ReadHeader` and `ReadValue`. `safeStorage`'s Linux `basic_text` backend
satisfies `IsEncryptionAvailable()` only when the app explicitly called
`setUsePlainTextEncryption(true)`, and `decryptString` rejects blobs lacking a v10/v11 prefix.
`Cookies::Set` refuses to overwrite an existing httpOnly cookie
(`EXCLUDE_OVERWRITE_HTTP_ONLY`). `SimpleURLLoaderWrapper::OnSSLCertificateError` fails closed.
`app.commandLine.appendSwitch`/`appendArgument` are not in any renderer module list.

**DevTools, extensions and OSR.** Remote debugging binds `TCPServerSocketFactory("127.0.0.1", port)`
only, with tethering disabled, `CreateNewTarget` returning `nullptr`, and the HTTP handler starting
only under `--remote-debugging-port`/`--remote-debugging-pipe` — no DNS-rebinding exposure.
`BundledDataSource` serves only the `bundled/` prefix. OSR frame-geometry checks are present and
correct: `osr_video_consumer.cc:167-192` clamps `content_rect` to `coded_size` **and** to
`mapping.size()` with `SkImageInfo::ByteSizeOverflowed`; `osr_host_display_client.cc:42-63` validates
`region.GetSize()`/`shm_mapping_.size()` before building the canvas. Extension
`AllowCrossRendererResourceLoad` and `PrepareURLForNavigation` are faithful ports of Chrome's, with
all devtools/chrome-untrusted/file/javascript/kill-URL gates present; native messaging is DISALLOW;
`GetElectronTabById` scopes by `BrowserContext`. Message boxes pass renderer strings as `"%s"`
arguments — no format-string issue.

**Patch risk register — deliberate relaxations examined and cleared.**
`short-circuit_permissions_checks_in_mediastreamdevicescontroller.patch` is **safe**: Electron's own
gate at `web_contents_permission_helper.cc:161-164` only reaches it inside `if (allowed)`.
`feat_allow_code_cache_in_custom_schemes.patch` is well constructed — cache segmentation preserved,
`CHECK_NE` guards prevent registering `chrome:`/`chrome-untrusted:`/`http(s)`, and the net effect on
`CheckSecurityForAccessingCodeCacheData` is **more** restrictive than upstream.
`feat_expose_raw_response_headers_from_urlloader.patch` is gated on
`trusted_params->report_raw_headers`, and `CorsURLLoaderFactory::IsValidRequest` rejects
`trusted_params` from renderer factories. The BoringSSL `expose_ripemd160`/`extra_cipher_functions`
patches make weak legacy primitives selectable from app JS but **do not affect TLS** — BoringSSL's
cipher-suite list and `x509_digest_verify_init`'s signature-NID table are separate tables these
patches do not touch. `refactor_allow_embedder_overriding_of_internal_fs_calls.patch` sets
`process.internalBinding`, and `lib/node/asar-fs-wrapper.ts:18-19` captures then **deletes** it.

*(One patch relaxation is worth flagging without calling it a bug:
`network_service_allow_remote_certificate_verification_logic.patch` lets app JS override TLS
verification via `setCertificateVerifyProc` — a documented API — but `verify_result->Reset()` clears
`cert_status`, `is_issued_by_known_root` and `public_key_hashes`, so CT and pinning operate on empty
data, and the `RemoteCertVerifier` is wrapped in an **outer** `net::CachingCertVerifier`, so app
decisions are cached and are not invalidated when the callback is replaced or cleared.)*

**Historical exposure windows that shipped and are now closed.** Worth recording because they
demonstrate the classes that recur: the contextBridge `VideoFrame` cross-realm wrapper leak
(`095e622a6` → fixed by `838d30510`) — the same class as
[C15](#c15-context-bridge-builds-thrown-errors-in-the-wrong-realm--medium), which is still open; the
`if (event.IsEmpty()) return;` guard silently dropped from all five entry points of
`ElectronApiIPCHandlerImpl`/`ElectronApiSWIPCHandlerImpl` by `e0db4046b`, leaving a
renderer-triggerable browser null deref open ~12 weeks until `530be28bc`; the offscreen
`window.open()` paint callback bound to the parent via `base::Unretained` (`880649990` → `222c989f1`);
and `session.clearData()` defaulting to `kClearDataTypeAll = ~0ULL`, which set
`DATA_TYPE_AVOID_CLOSING_CONNECTIONS` and silently left live connections open on a "clear everything"
call, shipped until `6f7999ad0`.

**Sustained hardening run (Mar–Jun 2026), none reverted.** OOR bounds on GPU-supplied OSR geometry;
a DevTools `dock_state_` allowlist before `ExecuteJavaScript`; header name/value validation;
protocol-scheme validation; USB device-list validation; **audit token instead of PID** for the macOS
parent code-signature check; hex-encoded notification temp filenames; a CORS gate for
`supportFetchAPI`-without-`corsEnabled` schemes; `IsSafeRedirectTarget` on net redirects; extension
tab-ID scoping; iframe sandbox-flag inheritance. Plus `1d14694de`, which removed the
`frameNamesToWindow` map from guest-window-manager — that map only ever matched when two *unrelated*
renderers used the same target name, letting one hijack the other's named window. And `a29e1170b`
wired Chrome's Web Serial and WebUSB device **blocklists** into Electron, which previously had none
at all.

---

## Coverage and limits

### What was read in full versus triaged

| Area | Read in full | Triaged / sampled |
|---|---|---|
| `shell/browser/api/electron_api_web_contents.cc` | All 5,227 lines, in 12 chunks | — |
| `shell/browser/net/` + `shell/common/asar/` | All 38 in-scope files | — |
| gin converters / gin_helper | All 29 converter files, all 35 gin_helper files, `v8_util.cc`, `node_bindings.cc` (1,221 lines) | mac `.mm` files not read; `electron_api_url_loader.cc` middle section skimmed |
| Renderer TypeScript | All 55 in-scope files (`lib/renderer`, `sandboxed_renderer`, `isolated_renderer`, `preload_realm`, `worker`, `utility`, `node`, `common`) | — |
| Context bridge | All 1,175 lines, twice | — |
| `shell/app/`, `shell/common/asar/`, `build/fuses/`, `npm/` | All files; complete 10-fuse callsite map | — |
| Patches | 63 read in full (45 chromium, 11 node, 4 v8, 2 boringssl, 1 perfetto) | All 248 triaged in three passes |

**Largest residual patch gap:** `revert_oscrypt_remove_sync_backend.patch` (6,504 lines, restoring the
deleted `components/os_crypt/sync` KWallet/libsecret backends) was token-scanned only. A line-by-line
review of the restored D-Bus parsing is a separate exercise. `mas_avoid_private_macos_api_usage.patch.patch`
(2,527 lines) was also not deep-read. Four headers (`base_window.h`, `browser_window.h`,
`web_contents_view.h`, `view.h`) and the `*_mac.mm` platform files in the window subsystem were not read.

### Per-window commit counts

| Window | Range | Commits | Triage |
|---|---|---|---|
| 1 | 2024-07-25 → 2025-01-25 | **518** | All 518 bucketed by `--name-only` (405 priority-path, 113 deprioritized); automated regex pass over every diff for **removed** lines matching ~30 security-check patterns → 64 flagged, all reviewed; 30 revert hits triaged; ~33 diffs read in full. Skipped: 47 rolls (pickaxe spot-checked), 64 docs/spec-only, 43 appveyor/dependabot, ~90 mechanical `-Wunsafe-buffer-usage`/clang-tidy refactors (4 sampled). |
| 2 | 2025-01-25 → 2025-07-25 | **604** (brief estimated ~520) | All 604 bucketed; 453 candidates after setting aside 44 rolls + 1 bulk patch refresh + 1 PGO update; **all 453** scored against 15 regex signals over added *and* removed lines, then a second per-hunk pass computing net guard removal surfaced 59 hunks across 47 commits, every one eyeballed; ~35 diffs read in full. Three targeted sub-audits: every patch file deleted in the window (~30), every method added to a renderer-exposed `.mojom` (exactly one), and all seven `pull_request_target`/`issue_comment` workflows. |
| 3 | 2025-07-25 → 2026-01-25 | **404** | All 404 triaged via a generated commit→path index; per-commit scan of every `shell/`,`lib/`,`patches/` diff counting deleted guard-pattern lines; `--grep=revert` sweep (23 hits); added-line scan for `base::Unretained`/`reinterpret_cast`/`ToLocalChecked`/`.value()`/`UNSAFE_BUFFERS`/`raw_ptr`; aggregate base→HEAD diff read for ~60 security-critical files; ~43 diffs read in full. Every candidate checked against the **working tree**, not just the diff — three dropped because fixed after the window, two more as unfounded. |
| 4 | 2026-01-25 → 2026-07-25 | **789** | All 789 triaged. Automated scan of removed lines under `shell/`,`lib/`,`patches/` against ~40 patterns, ranked by hit count, top 80 reviewed by hand; 12 security-critical files diffed **whole** from the pre-window base to HEAD; **every `*.mojom` in the tree** diffed (only 3 changed); ~47 diffs read in full, plus two delegated sweeps (all 137 `patches/` commits with every deleted patch checked against upstream at the pinned SHA, and all `lib/`,`.github/`,`script/`,`build/`,`fuses` commits with oxfmt/oxlint reformatting normalized away first). Skipped: 51 rolls (diffs *were* included in the removed-line scan), 51 docs-only, 41 spec-only. |

**Total: 2,315 commits, all triaged.**

**Self-declared gap:** window 2 flagged 10 commits in the renderer/context-bridge/preload slice
(`26da3c5d6`, `3c9b8475a`, `508c60199`, `c964296ec`, `376634c75`, `09ab71de4`, `307d4f94c`,
`a86e44b17`, `4f89c3195`, `3e51ee516`) that passed the mechanical signal scan without net guard
removal but received no full human read; the four highest-value ones were subsequently read and
nothing was found.

### Environment limits — read these before acting on any upstream claim

1. **There is no Chromium checkout in this environment.** `/home/user` contains only `electron`,
   **contrary to `CLAUDE.md`**, which states that the parent directory is the Chromium source. Every
   Chromium-side assertion in this report was either (a) verified against the DEPS-pinned upstream
   version (152.0.7962.2) fetched from the `chromium/chromium` GitHub mirror, or (b) explicitly
   flagged as unresolved. Treat all Chromium-side assertions as "verified against pinned upstream
   source, not against a local build".
2. **Two questions could not be resolved even against the mirror** because the files exceed the
   remote fetch size limit: `RenderFrameHostImpl::CreateWebUIImpl`/`AllowBindings` (the decisive step
   for [C3](#c3-webui-factory-matches-host-without-checking-scheme--medium-partially-refuted-could-fall-to-info))
   and whether `CorsURLLoaderFactory` sits below the appended proxy (the decisive step for the
   intercepted-scheme CORS variant). Both are called out inline.
3. **Nothing was built and nothing was run.** No exploit was demonstrated end to end. Every finding
   is source-derived. Where a claim depends on runtime behaviour that could not be observed —
   `ClipboardWin::ReadHTML` offset clamping, whether Node still accepts `--secure-heap` under the V8
   sandbox, whether `SetIsWebView`'s per-world `v8::Private` mismatch is real — it is recorded as a
   lead rather than a finding, and those leads are **not** counted in the 69.
4. **Two GitHub repository settings are not readable from the tree** and materially affect the
   severity of [A1](#a1-fork-pr-code-execution-on-self-hosted-runners-into-an-unverified-shared-source-cache--critical).
   See [Open items](#open-items).
5. **The release pipeline partly left the repository.** `9b79fb8d5` (2026-06-23) deleted 2,574 lines
   of release entry scripts as those responsibilities moved to Sudowoodo; the removed
   validate-before-publish step's replacement now lives **outside this repository** and is therefore
   outside the reach of this audit. Similarly, the `ssh-debug`/`setup-ssh.sh` rewrite removed the
   in-repo `AUTHORIZED_USERS` allowlist check against `$GITHUB_ACTOR`, replacing it with a Cloudflare
   Access SSH CA plus an `AuthorizedPrincipalsCommand` that echoes the presented certificate's own
   principals. Policy now lives in Cloudflare Zero Trust — **CI shell access is no longer gated by
   anything reviewable in-tree.** Neither is asserted to be a defect.

---

## Open items

These cannot be closed from this repository. Each needs someone with more access than this review had.

### 1. squirrel.mac auto-updater security patches dropped on an unverifiable assertion

`ea0954238` "build: update squirrel.mac to 8d808803, drop upstreamed patches (#51584)" (2026-05-12)
bumped squirrel.mac from `0e5d146ba1` to `8d808803bc` and deleted 14 patches. **Three carried
auto-updater security controls:**

- `add_ability_to_prevent_version_downgrades.patch` (116 lines)
- `..._signed_updates_before_downloading_new_update.patch` (130 lines)
- `..._mac_bundle_installation_method_behind_flag.patch` (128 lines)

The deleted patches contained privileged-install target validation and a
`kSecCSCheckNestedCode | kSecCSStrictValidate` code-signing check. Only `build_add_gn_config.patch`
remains, slimmed to GN-only changes. The commit message asserts these were upstreamed via
Squirrel/Squirrel.Mac#312 (mainly), plus #298, #302 and #308; `DEPS` pins
`squirrel.mac_version = 8d808803bc`.

**This is not a claim that the controls are missing** — it is very likely they were genuinely
upstreamed, as the commit says and the referenced PR numbers suggest. It is a verification item,
open only because `src/third_party/squirrel.mac` is not in this checkout. Three security controls
governing how a signed macOS app accepts and installs an update were removed from Electron's tree on
the basis that upstream now carries them, and that basis is not verifiable here.

To close it, with a full checkout:

```bash
cd src/third_party/squirrel.mac && git log --oneline -1     # confirm 8d808803bc
grep -rn "kSecCSCheckNestedCode\|kSecCSStrictValidate" .
grep -rn "downgrade\|SQRLUpdater.*version" .
```

### 2. Fork-PR workflow approval setting

Settings → Actions → General → "Fork pull request workflows from outside collaborators". The
public-repo default is *"Require approval for first-time contributors"*, which means **anyone with
one prior merged PR runs workflows automatically** — and under that default,
[A1](#a1-fork-pr-code-execution-on-self-hosted-runners-into-an-unverified-shared-source-cache--critical)
is CRITICAL as stated. If it is set to *"Require approval for all outside collaborators"*, the
code-execution half drops to MEDIUM. **The cache-integrity gap holds either way** and should be fixed
regardless of the setting.

Also unresolvable from the tree: the self-hosted runner-group access policy — which repositories and
which workflow events may schedule onto the `electron-arc-centralus-*` pools.

### 3. Whether code-owner review was enforced on `main`

No ruleset, branch-protection artifact or equivalent exists anywhere under `.github/`. If "Require
review from Code Owners" **was** enabled on `main`, then
[A2](#a2-codeowners-infra-sign-off-removed--low-downgraded-from-medium) is a legitimate MEDIUM
process regression worth raising with the Infra WG — the deleted entries covered
`.github/actions/`, `build.yml`, `pipeline-*.yml` and `*-publish.yml`, i.e. exactly the composite
actions that run as root on the self-hosted pool, mint SAS tokens and write the shared source cache.
If it was not enabled, the entries were auto-reviewer-assignment only and the removal is cosmetic.
Independently of that answer, `.github/CODEOWNERS:16` points at a deleted file and should be
repointed at `shell/browser/ui/devtools_context_menu.cc` and
`shell/browser/ui/inspectable_web_contents.cc`.
