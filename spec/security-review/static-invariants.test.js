'use strict';

// =============================================================================
// SECURITY-REVIEW CHARACTERIZATION SUITE
// =============================================================================
//
// READ THIS BEFORE "FIXING" A FAILURE.
//
// These are CHARACTERIZATION tests, not regression tests. Every test in this
// file asserts the DEFECTIVE SHAPE that currently exists in the source tree.
//
//   * A PASSING test means the defect is STILL PRESENT.
//   * A FAILING test means somebody FIXED the defect. That is the intended
//     signal, and it is good news.
//
// So when a test here goes red: do not repair the test to make it green
// again. Confirm the underlying defect really was fixed, then DELETE the test
// (and its entry in the security review) as resolved. The only legitimate
// "repair" is when the surrounding code was merely reformatted or moved and
// the defect itself survived - in that case re-anchor the test on the new
// code text.
//
// Assertions are anchored on CODE TEXT (indexOf / regex / brace matching),
// not on hard-coded line numbers, so that reformatting does not produce false
// "fixed!" signals. Line numbers that appear in test *names* are derived at
// runtime from the current tree.
//
// Constraints this file obeys:
//   * Node built-ins only (node:test, node:assert, node:fs, node:path,
//     node:child_process). No mocha, no chai, no ts-node.
//   * Nothing is imported from the Electron source tree; nothing is built.
//   * Run with:  node --test spec/security-review/
//
// =============================================================================

const test = require('node:test');
const assert = require('node:assert');

const {
  readRepoFile,
  repoFileExists,
  lineOf,
  lineTextAt,
  mustIndexOf,
  countOccurrences,
  matchBracket,
  findFunctionBody,
  enclosingBraces,
  conditionOfBlock,
  previousCodeChar,
  grepRepo
} = require('./helpers');

/**
 * Register a characterization test.
 *
 * `setup` performs the structural analysis and returns an object with a
 * `desc` property of the form "<short description> (<file>:<line>)", with the
 * line derived at runtime. Anything else it returns is handed to `body`.
 *
 * If `setup` throws (e.g. an anchor vanished because the defect was fixed or
 * the file was restructured), the test is still registered and fails loudly
 * rather than silently disappearing from the run.
 */
function defect (setup, body) {
  let ctx = null;
  let setupError = null;
  try {
    ctx = setup();
  } catch (err) {
    setupError = err;
  }
  const name = setupError
    ? 'DEFECT STILL PRESENT: <anchor lost - defect may have been fixed; see failure>'
    : `DEFECT STILL PRESENT: ${ctx.desc}`;
  test(name, () => {
    if (setupError) throw setupError;
    body(ctx);
  });
}

// =============================================================================
// 1. serial-forget-end-iterator-deref
// =============================================================================

defect(() => {
  const file = 'shell/browser/serial/serial_chooser_context.cc';
  const src = readRepoFile(file);
  const fn = findFunctionBody(src, 'SerialChooserContext::RevokePortPermissionWebInitiated(');

  // The iterator, and the guard that establishes it is dereferenceable.
  const itDecl = mustIndexOf(src, 'auto it = port_info_.find(token);', fn.bodyOpen, 'iterator declaration');
  const guardIf = mustIndexOf(src, 'if (it != port_info_.end())', itDecl, 'end() guard');
  const guardOpen = mustIndexOf(src, '{', guardIf, 'guard block open brace');
  const guardClose = matchBracket(src, guardOpen);

  // The later dereference.
  const deref = mustIndexOf(src, 'details.Set("port", it->second)', fn.bodyOpen, 'iterator dereference');

  return {
    desc: `end() iterator dereferenced outside its guard in RevokePortPermissionWebInitiated (${file}:${lineOf(src, deref)})`,
    src, fn, itDecl, guardIf, guardOpen, guardClose, deref
  };
}, (ctx) => {
  const { src, fn, itDecl, guardOpen, guardClose, deref } = ctx;

  // Structural proof, not a grep: everything is inside the one function...
  assert.ok(itDecl > fn.bodyOpen && itDecl < fn.bodyClose,
    'iterator declaration should be inside RevokePortPermissionWebInitiated');
  assert.ok(deref > fn.bodyOpen && deref < fn.bodyClose,
    'dereference should be inside RevokePortPermissionWebInitiated');

  // ...the guard block is well-formed and closes before the dereference...
  assert.ok(guardClose > guardOpen, 'guard block must brace-match');
  assert.strictEqual(src[guardClose], '}');

  // ...and THIS is the defect: the dereference sits AFTER the guard closed,
  // so `it` may still be port_info_.end() when `it->second` runs. Nothing
  // between the guard and the dereference re-establishes validity.
  assert.ok(deref > guardClose,
    `expected the dereference (line ${lineOf(src, deref)}) to be OUTSIDE the ` +
    `if (it != port_info_.end()) block, which closes at line ${lineOf(src, guardClose)}`);

  // Nothing re-checks the iterator in between.
  const between = src.slice(guardClose, deref);
  assert.ok(!between.includes('port_info_.end()'),
    'no second end() check should exist between the guard and the dereference');
  assert.ok(!between.includes('port_info_.find('),
    'the iterator should not be reassigned between the guard and the dereference');

  // A FIX would either (a) move the Emit/details work inside the guard block,
  // or (b) add `if (it == port_info_.end()) return;` after the find(). Either
  // makes `deref > guardClose` false (or removes the anchors entirely), so
  // this test would then FAIL - which is the signal we want.
});

// =============================================================================
// 2. fsa-revocation-dead-code
// =============================================================================

defect(() => {
  const file = 'shell/browser/file_system_access/file_system_access_web_contents_helper.h';
  const src = readRepoFile(file);
  const decl = mustIndexOf(src, 'class FileSystemAccessWebContentsHelper', 0, 'class declaration');
  return {
    desc: `FileSystemAccessWebContentsHelper compiled but never attached to any WebContents (${file}:${lineOf(src, decl)})`
  };
}, () => {
  const OWN_H = 'shell/browser/file_system_access/file_system_access_web_contents_helper.h';
  const OWN_CC = 'shell/browser/file_system_access/file_system_access_web_contents_helper.cc';
  const CTX_H = 'shell/browser/file_system_access/file_system_access_permission_context.h';

  // grepRepo skips out/, .git/, node_modules/ and this suite's own sources
  // (which necessarily quote the symbol they are searching for).
  const hits = grepRepo('FileSystemAccessWebContentsHelper');
  assert.ok(hits.length > 0, 'sanity: the class name should appear somewhere');

  // Every single mention lives in the class's own two files, filenames.gni,
  // or a comment. Nothing *uses* it.
  const allowed = new Set([OWN_H, OWN_CC, 'filenames.gni', CTX_H]);
  const stray = hits.filter((h) => !allowed.has(h.file));
  assert.deepStrictEqual(stray, [],
    'the only mentions of FileSystemAccessWebContentsHelper should be its own ' +
    'header/impl, filenames.gni, and a comment in file_system_access_permission_context.h');

  // The permission-context mention really is only a comment, not a call.
  for (const h of hits.filter((x) => x.file === CTX_H)) {
    assert.match(h.text.trim(), /^\/\//,
      `${CTX_H}:${h.line} should be a comment, but reads: ${h.text.trim()}`);
  }

  // THE DEFECT: WebContentsUserData subclasses only become live once
  // CreateForWebContents() is called. It never is - anywhere in the tree.
  // So DidFinishNavigation()/WebContentsDestroyed() never run and the
  // file-system-access permission revocation-on-navigation is dead code.
  const created = grepRepo('FileSystemAccessWebContentsHelper::CreateForWebContents');
  assert.deepStrictEqual(created, [],
    'expected ZERO calls to FileSystemAccessWebContentsHelper::CreateForWebContents');

  // It is compiled in, so this is not "an unused file nobody builds".
  const gni = readRepoFile('filenames.gni');
  assert.ok(gni.includes('shell/browser/file_system_access/file_system_access_web_contents_helper.cc'),
    'the helper is listed in filenames.gni, i.e. it is compiled into the binary');

  // CONTRAST, proving the attachment mechanism exists and works: the sibling
  // WebContentsUserData helper IS attached from electron_api_web_contents.cc.
  // The FSA helper was simply omitted from the same initialization path.
  const wcFile = 'shell/browser/api/electron_api_web_contents.cc';
  const wcSrc = readRepoFile(wcFile);
  const attach = wcSrc.indexOf('WebContentsPermissionHelper::CreateForWebContents(');
  assert.notStrictEqual(attach, -1,
    `${wcFile} should call WebContentsPermissionHelper::CreateForWebContents - ` +
    'this is the attachment mechanism the FSA helper is missing from');

  // A FIX adds FileSystemAccessWebContentsHelper::CreateForWebContents(...)
  // alongside that call, which makes the "ZERO calls" assertion fail.
});

// =============================================================================
// 3. mojo-binder-asymmetry
// =============================================================================

defect(() => {
  const file = 'shell/browser/electron_browser_client.cc';
  const src = readRepoFile(file);
  const fn = findFunctionBody(src, 'RegisterAssociatedInterfaceBindersForRenderFrameHost(');
  const utility = mustIndexOf(src, 'associated_registry.AddInterface<mojom::ElectronWebContentsUtility>',
    fn.bodyOpen, 'ElectronWebContentsUtility binder');
  return {
    desc: `ElectronWebContentsUtility bound to every frame while ElectronApiIPC is gated (${file}:${lineOf(src, utility)})`,
    file, src, fn, utility
  };
}, (ctx) => {
  const { src, fn, utility } = ctx;

  const apiIpc = mustIndexOf(src, 'associated_registry.AddInterface<mojom::ElectronApiIPC>',
    fn.bodyOpen, 'ElectronApiIPC binder');
  assert.ok(apiIpc < fn.bodyClose, 'ApiIPC binder should be in this function');
  assert.ok(utility < fn.bodyClose, 'WebContentsUtility binder should be in this function');

  const conditionsFor = (idx) =>
    enclosingBraces(src, fn.bodyOpen, idx)
      .filter((b) => b !== fn.bodyOpen)             // skip the function body itself
      .map((b) => conditionOfBlock(src, fn.bodyOpen, b));

  const apiIpcConditions = conditionsFor(apiIpc);
  const utilityConditions = conditionsFor(utility);

  // ElectronApiIPC IS gated: an enclosing block tests main-frame-ness OR the
  // nodeIntegrationInSubFrames preference.
  const gate = apiIpcConditions.find((c) => c.includes('AllowsNodeIntegrationInSubFrames'));
  assert.ok(gate,
    'ElectronApiIPC should be enclosed by a block whose condition mentions ' +
    `AllowsNodeIntegrationInSubFrames; enclosing conditions were: ${JSON.stringify(apiIpcConditions)}`);
  assert.ok(gate.includes('GetPrimaryMainFrame'),
    'the ApiIPC gate should be the main-frame-or-subframe-node-integration test');

  // THE DEFECT: ElectronWebContentsUtility has NO such gate. It is registered
  // unconditionally, so every subframe - including cross-origin iframes in a
  // window with nodeIntegrationInSubFrames disabled - can reach the utility
  // interface (preload code cache writes, clipboard checks, ...) even though
  // the sibling IPC interface was deliberately withheld from them.
  assert.ok(!utilityConditions.some((c) => c.includes('AllowsNodeIntegrationInSubFrames')),
    'ElectronWebContentsUtility should NOT be gated on AllowsNodeIntegrationInSubFrames ' +
    `(that is the defect); enclosing conditions were: ${JSON.stringify(utilityConditions)}`);
  assert.deepStrictEqual(utilityConditions, [],
    'ElectronWebContentsUtility should sit at the top level of the function, ' +
    'inside no conditional block at all');

  // And it really is the *same* function, so this is a genuine asymmetry and
  // not two different registration paths with different contracts.
  assert.ok(utility > fn.bodyOpen && apiIpc > fn.bodyOpen,
    'both binders are registered by RegisterAssociatedInterfaceBindersForRenderFrameHost');

  // A FIX wraps the WebContentsUtility AddInterface in the same main-frame /
  // AllowsNodeIntegrationInSubFrames conditional, which makes the
  // "utilityConditions is empty" assertion fail.
});

// =============================================================================
// 4. preload-code-cache-trusts-renderer-hash
// =============================================================================

defect(() => {
  const file = 'shell/browser/electron_web_contents_utility_handler_impl.cc';
  const src = readRepoFile(file);
  const fn = findFunctionBody(src, 'ElectronWebContentsUtilityHandlerImpl::SetPreloadCodeCache(');
  return {
    desc: `browser stores renderer-supplied source_hash without re-deriving it (${file}:${lineOf(src, fn.anchor)})`,
    file, src, fn
  };
}, (ctx) => {
  const { src, fn } = ctx;

  const signature = src.slice(fn.anchor, fn.bodyOpen);
  assert.ok(signature.includes('const std::vector<uint8_t>& source_hash'),
    `SetPreloadCodeCache should take source_hash straight from the renderer; signature was: ${signature}`);

  // The parameter is forwarded verbatim to the persistent cache.
  assert.ok(fn.body.includes('preload_code_cache::Set(id, source_hash,'),
    'the renderer-supplied hash should be passed directly to preload_code_cache::Set');

  // THE DEFECT: the browser never recomputes the hash of the preload source it
  // actually served, so a compromised renderer can key an arbitrary V8 code
  // cache blob under any hash it likes.
  assert.ok(!fn.body.includes('crypto::hash::Sha256'),
    'SetPreloadCodeCache should contain NO browser-side hash derivation (that is the defect)');
  assert.strictEqual(countOccurrences(src, 'crypto::hash::Sha256'), 0,
    'the whole handler translation unit should never hash anything');

  // And on the storage side, the ONLY hash the browser ever computes is over
  // the preload *source*, on read - never over the cache blob it was handed.
  const cacheFile = 'shell/browser/preload_code_cache.cc';
  const cacheSrc = readRepoFile(cacheFile);
  assert.ok(cacheSrc.includes('entry->source_hash != crypto::hash::Sha256(contents)'),
    `${cacheFile} Get() should compare the stored hash against Sha256 of the preload source`);

  // Enumerate every Sha256 call site: none of them hashes the blob.
  const hashArgs = [...cacheSrc.matchAll(/crypto::hash::Sha256\(([^)]*)\)/g)].map((m) => m[1]);
  assert.ok(hashArgs.length > 0, 'sanity: preload_code_cache.cc does hash something');
  assert.deepStrictEqual([...new Set(hashArgs)].sort(), ['contents', 'id'],
    `the browser only ever hashes the cache id and the preload source, never the blob; saw: ${JSON.stringify(hashArgs)}`);
  assert.ok(!/crypto::hash::Sha256\(\s*blob/.test(cacheSrc),
    'the blob itself is never hashed or otherwise authenticated');

  // A FIX has the browser read the preload source it served and compute
  // crypto::hash::Sha256 over it in SetPreloadCodeCache (ignoring or
  // cross-checking the renderer value), which makes the
  // "no crypto::hash::Sha256 in this file" assertions fail.
});

// =============================================================================
// 5. webview-attach-dcheck-only
// =============================================================================

defect(() => {
  const file = 'shell/browser/web_view_guest_delegate.cc';
  const src = readRepoFile(file);
  const fn = findFunctionBody(src, 'WebViewGuestDelegate::AttachToIframe(');
  const dcheck = mustIndexOf(src, 'DCHECK_EQ', fn.bodyOpen, 'ownership DCHECK');
  return {
    desc: `embedder frame ownership enforced only by DCHECK_EQ in AttachToIframe (${file}:${lineOf(src, dcheck)})`,
    file, src, fn
  };
}, (ctx) => {
  const { src, fn } = ctx;

  const lookup = mustIndexOf(src, 'RenderFrameHost::FromFrameToken(', fn.bodyOpen, 'frame token lookup');
  const attach = mustIndexOf(src, 'AttachInnerWebContents(', lookup, 'inner WebContents attach');
  assert.ok(attach < fn.bodyClose, 'both anchors should be inside AttachToIframe');

  // Everything the function does between resolving the renderer-supplied
  // frame token and committing the attachment.
  const between = src.slice(lookup, attach);

  // THE DEFECT: the sole check that the resolved frame actually belongs to the
  // embedder WebContents is a DCHECK_EQ, which compiles away entirely in
  // release builds. A renderer that supplies a frame token belonging to a
  // different WebContents gets its guest attached there with no enforcement.
  assert.ok(between.includes('DCHECK_EQ'),
    'the ownership check between token resolution and attach should be a DCHECK_EQ');
  assert.ok(!/\bif\s*\(/.test(between),
    `there should be NO runtime conditional between token resolution and attach ` +
    `(that is the defect); text was:\n${between}`);
  assert.ok(!/\breturn\b/.test(between),
    'there should be no early return rejecting a foreign frame');
  assert.ok(!/\bCHECK\b|\bCHECK_EQ\b|\bmojo::ReportBadMessage\b|\bbad_message\b/.test(between),
    'there should be no release-build-surviving check either');

  // The DCHECK really is comparing the resolved frame's WebContents against
  // the embedder, i.e. it is the ownership check and not something unrelated.
  assert.ok(between.includes('WebContents::FromRenderFrameHost(embedder_frame)'),
    'the DCHECK_EQ compares the embedder WebContents against the token-resolved frame');

  // A FIX replaces the DCHECK_EQ with a real `if (...) { ReportBadMessage(); return; }`,
  // which makes the "no if (" and "no return" assertions fail.
});

// =============================================================================
// 6. webview-partition-unvalidated
// =============================================================================

defect(() => {
  const file = 'lib/browser/guest-view-manager.ts';
  const src = readRepoFile(file);
  const at = mustIndexOf(src, 'partition: params.partition', 0, 'partition passthrough');
  return {
    desc: `<webview> partition attribute forwarded unvalidated and never inherited-locked (${file}:${lineOf(src, at)})`,
    file, src, at
  };
}, (ctx) => {
  const { src, at } = ctx;

  // ---- (a) JS side: the attribute goes straight into webPreferences ----
  assert.ok(at !== -1, 'guest-view-manager should forward params.partition verbatim');
  assert.match(lineTextAt(src, at).trim(), /^partition: params\.partition,?$/,
    'the partition attribute is copied with no sanitizing wrapper');

  // The security options a guest is FORCED to inherit from its embedder.
  const mapStart = mustIndexOf(src, 'const inheritedWebPreferences = new Map(', 0, 'inherited prefs map');
  const arrOpen = mustIndexOf(src, '[', mapStart, 'inherited prefs array');
  const arrClose = matchBracket(src, arrOpen);
  const mapLiteral = src.slice(arrOpen, arrClose + 1);
  const inheritedKeys = [...mapLiteral.matchAll(/\['([^']+)'\s*,/g)].map((m) => m[1]);
  assert.ok(inheritedKeys.length > 0, 'sanity: some prefs are inherited');

  // THE DEFECT (a): 'partition' is NOT in that list, so an attacker-controlled
  // <webview partition="..."> escapes the embedder's session entirely - it can
  // name the embedder's own persist: partition, or a brand new one.
  assert.ok(!inheritedKeys.includes('partition'),
    `'partition' should NOT be an inherited/locked web preference (that is the defect); ` +
    `inherited keys are: ${JSON.stringify(inheritedKeys)}`);
  assert.ok(inheritedKeys.includes('contextIsolation') && inheritedKeys.includes('sandbox'),
    'sanity: other security-relevant prefs ARE locked, so the omission is selective');

  // ---- (b) C++ side: the partition string is never validated ----
  const cxxFile = 'shell/browser/api/electron_api_session.cc';
  const cxx = readRepoFile(cxxFile);
  const fn = findFunctionBody(cxx, 'Session* Session::FromPartition(');

  assert.ok(fn.body.includes('partition.substr(8)'),
    'FromPartition strips the "persist:" prefix with a bare substr(8)');

  // Slice from the substr to the browser-context creation: nothing in between
  // inspects the resulting name.
  const substrAt = mustIndexOf(cxx, 'partition.substr(8)', fn.bodyOpen, 'persist prefix strip');
  const useAt = mustIndexOf(cxx, 'ElectronBrowserContext::From(name', substrAt, 'browser context creation');
  const between = cxx.slice(substrAt, useAt);
  assert.ok(!/\bif\s*\(/.test(between),
    `no validation conditional should exist between substr(8) and ElectronBrowserContext::From ` +
    `(that is the defect); text was: ${JSON.stringify(between)}`);

  // THE DEFECT (b): the whole function contains no path-traversal rejection,
  // no separator rejection, and no length/charset check. The partition name
  // becomes an on-disk directory name.
  for (const guard of ['..', 'ThrowTypeError', 'IsStringUTF8', 'base::FilePath',
    'IsValid', 'kSeparators', 'FILE_PATH_LITERAL', 'ReferencesParent']) {
    assert.ok(!fn.body.includes(guard),
      `FromPartition should contain no ${JSON.stringify(guard)} validation (that is the defect)`);
  }

  // A FIX either adds 'partition' to inheritedWebPreferences, or adds a
  // rejection for traversal/separator characters in FromPartition. Either one
  // makes the corresponding negative assertion above fail.
});

// =============================================================================
// 7. asar-integrity-macos-bundle-mismatch
// =============================================================================

defect(() => {
  const file = 'shell/common/asar/archive_mac.mm';
  const src = readRepoFile(file);
  const at = mustIndexOf(src, 'base::apple::MainBundlePath()', 0, 'bundle path lookup');
  return {
    desc: `asar integrity resolves the bundle differently from the rest of Electron on macOS (${file}:${lineOf(src, at)})`,
    file, src, at
  };
}, (ctx) => {
  const { src } = ctx;

  // THE DEFECT: asar integrity computes the archive's bundle-relative path
  // using base::apple::MainBundlePath(), which in a helper process is the
  // *helper's* bundle, not the outer .app. It does not use Electron's own
  // helper-correcting resolver.
  assert.ok(src.includes('base::apple::MainBundlePath()'),
    'archive_mac.mm resolves the bundle with base::apple::MainBundlePath()');
  assert.ok(!src.includes('MainApplicationBundlePath'),
    'archive_mac.mm should NOT use electron::MainApplicationBundlePath() (that is the defect)');
  assert.ok(!src.includes('shell/common/mac/main_application_bundle.h'),
    'archive_mac.mm does not even include the helper-correcting resolver');

  // It also reads the integrity dictionary from [NSBundle mainBundle], the
  // same uncorrected bundle - so both halves of the check drift together.
  assert.ok(src.includes('[[NSBundle mainBundle]'),
    'the ElectronAsarIntegrity dictionary is read from the uncorrected mainBundle');

  // CONTRAST: Electron ships a resolver that explicitly walks out of the
  // helper bundle. Its existence is what makes archive_mac.mm's choice a bug
  // rather than an accepted limitation.
  const bundleFile = 'shell/common/mac/main_application_bundle.mm';
  const bundleSrc = readRepoFile(bundleFile);
  assert.ok(bundleSrc.includes('MainApplicationBundlePath'),
    `${bundleFile} defines the corrected resolver`);
  assert.ok(
    bundleSrc.includes('DirName().DirName().DirName().DirName().DirName()') ||
    bundleSrc.includes('Go up five steps'),
    `${bundleFile} performs the helper-correcting five-level walk`);
  assert.ok(bundleSrc.includes('kMacHelperSuffix_renderer'),
    'the corrected resolver explicitly recognises renderer/gpu/plugin helper executables');

  // The divergence IS the proof: two resolvers, and the security-relevant one
  // picked the uncorrected one.
  assert.notStrictEqual(
    src.includes('base::apple::MainBundlePath()'),
    src.includes('MainApplicationBundlePath'),
    'archive_mac.mm uses exactly one of the two resolvers, and it is the wrong one');

  // A FIX switches archive_mac.mm to electron::MainApplicationBundlePath(),
  // which makes the "should NOT use MainApplicationBundlePath" assertion fail.
});

// =============================================================================
// 8. webui-factory-no-scheme-check
// =============================================================================

defect(() => {
  const file = 'shell/browser/electron_web_ui_controller_factory.cc';
  const src = readRepoFile(file);
  const fn = findFunctionBody(src, 'ElectronWebUIControllerFactory::GetWebUIType(');
  return {
    desc: `GetWebUIType matches on host alone with no scheme check (${file}:${lineOf(src, fn.anchor)})`,
    file, src, fn
  };
}, (ctx) => {
  const { src, fn } = ctx;

  // THE DEFECT: WebUI selection is decided purely by url.host(). Any scheme
  // that reaches this factory with host "chrome-devtools" or "accessibility"
  // gets a privileged WebUI controller.
  assert.ok(fn.body.includes('url.host()'),
    'GetWebUIType keys off url.host()');
  assert.ok(!fn.body.includes('SchemeIs'),
    'GetWebUIType should contain NO scheme check (that is the defect)');
  assert.strictEqual(countOccurrences(src, 'SchemeIs'), 0,
    'the whole factory translation unit never checks a scheme');
  assert.ok(!fn.body.includes('kChromeUIScheme'),
    'GetWebUIType never compares against the chrome:// scheme constant');

  // The controller factory really does hand out privileged controllers.
  assert.ok(src.includes('CreateWebUIControllerForURL'),
    'sanity: this factory constructs WebUI controllers');

  // CONTRAST between the two controllers it can construct: DevToolsUI
  // deliberately clamps its bindings, the accessibility UI does not clamp
  // anything - so an unexpected scheme reaching the factory is not uniformly
  // harmless.
  const devtoolsFile = 'shell/browser/ui/devtools_ui.cc';
  const devtools = readRepoFile(devtoolsFile);
  assert.ok(devtools.includes('SetBindings'),
    `${devtoolsFile} explicitly narrows its WebUI bindings`);

  const a11yFile = 'shell/browser/ui/webui/accessibility_ui.cc';
  const a11y = readRepoFile(a11yFile);
  assert.ok(!a11y.includes('SetBindings'),
    `${a11yFile} should contain NO SetBindings call (it never narrows bindings)`);

  // A FIX adds `url.SchemeIs(content::kChromeUIScheme)` to the GetWebUIType
  // condition, which makes the "no SchemeIs" assertions fail.
});

// =============================================================================
// 9. webview-cross-drag-patch
// =============================================================================

defect(() => {
  const file = 'patches/chromium/webview_cross_drag.patch';
  const src = readRepoFile(file);
  const at = mustIndexOf(src, '+  return true;', 0, 'unconditional-true replacement');
  return {
    desc: `drag-target site-instance-group check patched out to an unconditional true (${file}:${lineOf(src, at)})`,
    file, src
  };
}, (ctx) => {
  const { src } = ctx;

  // THE DEFECT: the Electron patch deletes Chromium's cross-SiteInstanceGroup
  // drag-target validation outright and returns true for every target, so a
  // drag payload can be delivered into an unrelated renderer.
  const removed = /^-\s*return target_rwh->GetSiteInstanceGroup\(\)->GetId\(\) == site_instance_group_id_;\s*$/m;
  assert.match(src, removed,
    'the patch should REMOVE the site-instance-group equality check');

  const added = /^\+\s*return true;\s*$/m;
  assert.match(src, added,
    'the patch should ADD an unconditional `return true;`');
  assert.ok(src.includes('+  return true;'),
    'the replacement line is exactly `+  return true;`');

  // It is patching the drag security validator, not some unrelated helper.
  assert.ok(src.includes('web_contents_view_drag_security_info.cc'),
    'the patched file is the drag security info validator');
  assert.ok(src.includes('IsValidDragTarget'),
    'the patched function is IsValidDragTarget');

  // Nothing is put back in its place: the hunk has exactly one added line and
  // one removed line.
  const addedLines = src.split('\n').filter((l) => l.startsWith('+') && !l.startsWith('+++'));
  const removedLines = src.split('\n').filter((l) => l.startsWith('-') && !l.startsWith('---'));
  assert.strictEqual(addedLines.length, 1,
    `the patch adds exactly one line (no replacement check); added: ${JSON.stringify(addedLines)}`);
  assert.strictEqual(removedLines.length, 1,
    `the patch removes exactly one line; removed: ${JSON.stringify(removedLines)}`);

  // A FIX replaces `return true;` with a narrower predicate (e.g. allowing
  // cross-group drags only between guests of the same embedder), which makes
  // the `+  return true;` assertions fail.
});

// =============================================================================
// 10. ipc-dispatch-shared-array
// =============================================================================

defect(() => {
  const file = 'lib/browser/ipc-dispatch.ts';
  const src = readRepoFile(file);
  const decl = mustIndexOf(src, 'const cachedIpcEmitters', 0, 'module-scope cache');
  return {
    desc: `getIpcEmittersForFrameEvent returns one shared module-scope array (${file}:${lineOf(src, decl)})`,
    file, src, decl
  };
}, (ctx) => {
  const { src, decl } = ctx;

  // THE DEFECT (part 1): the cache is a single module-scope array, shared by
  // every WebContents and every dispatch, not a per-call allocation.
  assert.match(src, /^const cachedIpcEmitters\b/m,
    'cachedIpcEmitters should be a top-level const at column 0 (module scope), not function-local');
  assert.strictEqual(lineTextAt(src, decl).indexOf('const'), 0,
    'the declaration starts at column 0, confirming module scope');
  assert.strictEqual(countOccurrences(src, 'const cachedIpcEmitters'), 1,
    'there is exactly one such array for the whole process');

  const fn = findFunctionBody(src, 'const getIpcEmittersForFrameEvent =');

  // THE DEFECT (part 2): the function mutates that shared array in place...
  assert.ok(/cachedIpcEmitters\[0\]\s*=/.test(fn.body),
    'getIpcEmittersForFrameEvent assigns cachedIpcEmitters[0]');
  assert.ok(/cachedIpcEmitters\[1\]\s*=/.test(fn.body),
    'getIpcEmittersForFrameEvent assigns cachedIpcEmitters[1]');

  // ...and hands out that same array rather than a copy. Any caller that holds
  // the result across an await or a re-entrant emit observes another frame's
  // emitters - including a different WebContents'.
  assert.match(fn.body, /return\s+cachedIpcEmitters\s*;/,
    'it returns the shared array itself');
  assert.ok(!/return\s*\[\s*\.\.\.\s*cachedIpcEmitters/.test(fn.body),
    'it does NOT return a spread copy (that is the defect)');
  assert.ok(!/cachedIpcEmitters\.slice\(\)/.test(fn.body),
    'it does NOT return a .slice() copy (that is the defect)');
  assert.ok(!fn.body.includes('structuredClone'),
    'it does not clone the array in any other way');

  // The hazard is real because the result is consumed by an async handler.
  assert.ok(countOccurrences(src, 'getIpcEmittersForFrameEvent(event)') > 1,
    'sanity: multiple dispatch paths share this one array');
  const invoke = findFunctionBody(src, "'-ipc-invoke' as any");
  assert.ok(invoke.body.includes('getIpcEmittersForFrameEvent(event)'),
    'the async -ipc-invoke handler consumes the shared array');
  assert.ok(/\basync\b/.test(invoke.body) || src.includes('async function'),
    'that handler is async, so the array can be mutated under it');

  // A FIX returns a fresh array (or a spread/slice of the cache), which makes
  // the `return cachedIpcEmitters;` assertion fail.
});

// =============================================================================
// 11. invoke-frame-granularity-mismatch
// =============================================================================

defect(() => {
  const file = 'lib/browser/ipc-main-internal-utils.ts';
  const src = readRepoFile(file);
  const at = mustIndexOf(src, 'event.sender !== sender', 0, 'coarse WebContents-level guard');
  return {
    desc: `invokeInWebContents authenticates replies per-WebContents while its sibling does it per-frame (${file}:${lineOf(src, at)})`,
    file, src
  };
}, (ctx) => {
  const { src } = ctx;

  const wc = findFunctionBody(src, 'export function invokeInWebContents');
  const wfm = findFunctionBody(src, 'export function invokeInWebFrameMain');

  // THE DEFECT: two sibling helpers, same reply-channel pattern, but different
  // authentication granularity. invokeInWebContents only checks that the reply
  // came from the right *WebContents*, so ANY frame in that WebContents -
  // including a cross-origin iframe or a <webview>-hosted frame - can forge
  // the reply to a request that was sent to a specific frame.
  assert.ok(wc.body.includes('event.sender !== sender'),
    'invokeInWebContents guards only on the WebContents identity');
  assert.ok(!wc.body.includes('frameTreeNodeId'),
    'invokeInWebContents does NOT compare frame identity (that is the defect)');
  assert.ok(!wc.body.includes('event.frameId') && !wc.body.includes('event.processId'),
    'invokeInWebContents does not compare any per-frame identifier either');

  // The sibling shows the stricter check was available all along.
  assert.ok(wfm.body.includes('event.frameTreeNodeId !== frameTreeNodeId'),
    'invokeInWebFrameMain guards on the frame tree node id');

  // Both otherwise share the same shape - same channel construction, same
  // "unexpected sender" bail-out - so the asymmetry is the finding.
  for (const fn of [wc, wfm]) {
    assert.ok(fn.body.includes('_RESPONSE_${requestId}'),
      'both helpers build the same reply channel name');
    assert.ok(fn.body.includes("event.type !== 'frame'"),
      'both helpers perform the same frame-type check');
    assert.ok(fn.body.includes('Reply to ${command} sent by unexpected sender'),
      'both helpers log the same rejection message');
  }
  assert.notStrictEqual(
    wc.body.includes('frameTreeNodeId'),
    wfm.body.includes('frameTreeNodeId'),
    'exactly one of the two siblings performs frame-granular authentication');

  // A FIX gives invokeInWebContents a frame-granular check too (capturing the
  // target frame and comparing frameTreeNodeId/processId+frameId), which makes
  // the "does NOT compare frame identity" assertion fail.
});

// =============================================================================
// 12. webrequest-filter-parse-error-ignored
// =============================================================================

defect(() => {
  const file = 'shell/browser/api/electron_api_web_request.cc';
  const src = readRepoFile(file);
  const fn = findFunctionBody(src, 'void WebRequest::SetListener(');
  const at = mustIndexOf(src, 'filter.AddUrlPatterns(', fn.bodyOpen, 'unchecked pattern parse');
  return {
    desc: `AddUrlPatterns parse failures are ignored while sibling type parsing bails out (${file}:${lineOf(src, at)})`,
    file, src, fn
  };
}, (ctx) => {
  const { src, fn } = ctx;

  // THE DEFECT (part 1): the helper cannot report failure at all - it returns
  // void, so a malformed URL pattern silently produces a filter that does not
  // match what the app asked for (typically matching more than intended).
  const header = readRepoFile('shell/browser/api/electron_api_web_request.h');
  assert.match(header, /\bvoid\s+AddUrlPatterns\s*\(/,
    'AddUrlPatterns is declared returning void, so it cannot signal a parse error');
  assert.ok(!/\bbool\s+AddUrlPatterns\s*\(/.test(header),
    'AddUrlPatterns does not return a success flag');

  // THE DEFECT (part 2): the call sites are bare statements - no `if (...)`
  // wrapper, no return value consumed.
  const calls = [...fn.body.matchAll(/filter\.AddUrlPatterns\(/g)].map((m) => m.index + fn.bodyOpen);
  assert.ok(calls.length >= 2, `expected the include and exclude pattern calls; found ${calls.length}`);
  for (const at of calls) {
    const line = lineTextAt(src, at).trim();
    assert.ok(line.startsWith('filter.AddUrlPatterns('),
      `AddUrlPatterns should be a bare statement, but its line reads: ${line}`);
    assert.ok(!/\bif\s*\(/.test(line),
      `AddUrlPatterns should NOT be wrapped in an if (that is the defect); line: ${line}`);
    const prev = previousCodeChar(src, at);
    assert.ok([';', '{', '}'].includes(prev),
      `AddUrlPatterns should follow a statement boundary (saw ${JSON.stringify(prev)}), ` +
      'confirming it is a discarded statement rather than part of a condition');
    assert.match(line, /\)\s*;$/, 'the call result is discarded');
  }

  // CONTRAST inside the very same function: the resource-type loop DOES detect
  // a bad value, throws, and returns - so the omission for URL patterns is an
  // inconsistency, not a deliberate house style.
  const loopAt = mustIndexOf(src, 'for (const std::string& filter_type : filter_types)', fn.bodyOpen, 'type loop');
  const loopOpen = mustIndexOf(src, '{', loopAt, 'type loop body');
  const loopBody = src.slice(loopOpen, matchBracket(src, loopOpen) + 1);
  assert.ok(loopBody.includes('ThrowTypeError'),
    'the filter_types loop rejects an invalid value');
  assert.match(loopBody, /\breturn\s*;/,
    'the filter_types loop aborts SetListener on an invalid value');
  assert.ok(loopAt > calls[calls.length - 1],
    'the strict type handling sits immediately after the lax pattern handling');

  // A FIX makes AddUrlPatterns return bool and wraps the call sites in
  // `if (!filter.AddUrlPatterns(...)) return;`, which makes the header `void`
  // assertion and the bare-statement assertions fail.
});

// =============================================================================
// 13. codeowners-ci-paths-unowned
// =============================================================================

defect(() => {
  const file = '.github/CODEOWNERS';
  const src = readRepoFile(file);
  const at = mustIndexOf(src, '/lib/browser/devtools.ts', 0, 'stale Security WG rule');
  return {
    desc: `CODEOWNERS leaves CI definitions unowned and keeps a rule for a deleted file (${file}:${lineOf(src, at)})`,
    file, src
  };
}, (ctx) => {
  const { src } = ctx;

  const entries = src.split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => l.split(/\s+/)[0]);
  assert.ok(entries.length > 0, 'sanity: CODEOWNERS has entries');

  // THE DEFECT (part 1): nothing owns the workflows or composite actions, so a
  // change to CI - which runs with repository credentials - needs no review
  // from any working group.
  const ciOwned = entries.filter((e) => /^\/?\.github\/(actions|workflows)\b/.test(e));
  assert.deepStrictEqual(ciOwned, [],
    `expected NO CODEOWNERS entry for .github/actions or .github/workflows; found ${JSON.stringify(ciOwned)}`);

  // Those directories do exist and do contain CI definitions.
  assert.ok(repoFileExists('.github/workflows'), '.github/workflows exists in the tree');
  assert.ok(repoFileExists('.github/actions'), '.github/actions exists in the tree');

  // Other .github paths ARE owned, so the file is not simply unused.
  assert.ok(entries.some((e) => e.startsWith('/.claude/')),
    'sanity: CODEOWNERS does own other infrastructure paths');

  // THE DEFECT (part 2): a Security WG rule points at a file that no longer
  // exists, so the rule can never fire - dead coverage that reads as coverage.
  assert.ok(entries.includes('/lib/browser/devtools.ts'),
    'the Security WG rule for /lib/browser/devtools.ts is still present');
  assert.strictEqual(repoFileExists('lib/browser/devtools.ts'), false,
    'lib/browser/devtools.ts should NOT exist on disk (that is what makes the rule dead)');

  // The neighbouring Security WG rules DO point at real files, so this is one
  // stale entry rather than a wholesale relocation.
  for (const live of ['lib/browser/guest-view-manager.ts', 'lib/browser/rpc-server.ts',
    'lib/renderer/security-warnings.ts']) {
    assert.ok(entries.includes(`/${live}`), `CODEOWNERS owns ${live}`);
    assert.ok(repoFileExists(live), `${live} exists, unlike devtools.ts`);
  }

  // A FIX adds an owner for /.github/workflows/ and drops (or re-points) the
  // devtools.ts rule, which makes the "no CI entry" and "file does not exist"
  // assertions fail respectively.
});

// =============================================================================
// 14. cookie-docs-code-mismatch
// =============================================================================

defect(() => {
  const file = 'shell/browser/api/electron_api_cookies.cc';
  const src = readRepoFile(file);
  const at = mustIndexOf(src, 'cookie.IsDomainMatch(*str)', 0, 'domain filter');
  return {
    desc: `cookies.get() domain filter uses the delivery predicate while docs promise subdomain matching (${file}:${lineOf(src, at)})`,
    file, src
  };
}, (ctx) => {
  const { src } = ctx;

  // THE DEFECT: net::CanonicalCookie::IsDomainMatch(host) answers "would this
  // cookie be SENT to `host`?". The filter argument is being passed as the
  // host, so the relation is evaluated in the delivery direction - the exact
  // opposite of "cookies whose domain is a subdomain of the filter".
  assert.ok(src.includes('cookie.IsDomainMatch(*str)'),
    'the domain filter delegates to CanonicalCookie::IsDomainMatch');
  const at = src.indexOf('cookie.IsDomainMatch(*str)');
  assert.ok(lineTextAt(src, at).includes('FindString("domain")'),
    'the filter string being passed as the "host" argument is the user-supplied domain filter');

  // The old bespoke subdomain-walking predicate is gone.
  assert.ok(!/\bbool\s+MatchesDomain\s*\(/.test(src),
    'the old MatchesDomain helper no longer exists');
  assert.ok(!src.includes('MatchesDomain('),
    'nothing calls MatchesDomain any more');

  // The documentation still describes the OLD relation.
  const docsFile = 'docs/api/cookies.md';
  const docs = readRepoFile(docsFile);
  assert.ok(docs.includes('subdomains of'),
    `${docsFile} still promises "match or are subdomains of" for the domain filter`);
  assert.match(docs, /Retrieves cookies whose domains match or are\s*\n?\s*subdomains of/,
    'the documented contract is subdomain-of-the-filter, not send-to-the-filter');

  // See cookie-domain-match.test.js for an executable proof that these two
  // relations genuinely disagree.

  // A FIX either restores a subdomain-of-filter predicate in the C++, or
  // rewrites docs/api/cookies.md to describe the delivery semantics. Either
  // makes one of the two assertions above fail.
});
