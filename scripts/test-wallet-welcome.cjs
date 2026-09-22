const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(process.argv[2] || path.join(__dirname, '../GUIWALLET/src/index.html'), 'utf8');
const inline = html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(inline); // The entire inline script must parse before buttons work.
const elements = new Map();
function element() { return {style:{}, setAttribute(){}, insertAdjacentElement(where, child) {elements.set(child.id, child);}}; }
elements.set('existingCoreWalletBox', element());
elements.set('welcomePassphrase', {value:'test-only-passphrase'});
let calls=0, opened=false;
const context = vm.createContext({
  $: id=>elements.get(id), document:{createElement:element},
  val:()=> 'test-wallet', appState:{network:'regtest'},
  invoke:async()=>{calls++;throw new Error('Could not find sidecar binary: qrx');},
  setActiveWalletName(){}, markWalletSessionReady(){},
  bootApp(){opened=true;}, showBanner(){}
});
for (const name of ['showWelcomeStatus','welcomeCreateWallet']) {
  const fn=inline.match(new RegExp('(?:async )?function '+name+'\\([^]*?^}', 'm'));
  assert.ok(fn, name); vm.runInContext(fn[0],context);
}
(async()=>{
  await vm.runInContext('welcomeCreateWallet()',context);
  assert.equal(calls,1); assert.equal(opened,false);
  const status=elements.get('welcomeActionStatus');
  assert.ok(status); assert.equal(status.style.display,'block');
  assert.match(status.textContent,/Wallet creation failed:.*Could not find sidecar/);
  context.invoke=async()=>({recovery_phrase:'test-only-recovery'});
  await vm.runInContext('welcomeCreateWallet()',context);
  assert.equal(opened,true);
  assert.equal(context.appState.freshRecoveryPhrase,'test-only-recovery');
  console.log('PASS: fresh-install creation errors visible, successful creation opens wallet and retains recovery phrase');
})().catch(e=>{console.error(e);process.exitCode=1;});
