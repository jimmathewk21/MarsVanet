/* Node's built-in test runner checks presentation logic without a browser or network. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', 'static', 'app.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '..', 'static', 'index.html'), 'utf8');
const nodes = new Map();
const document = {
  addEventListener() {},
  getElementById(id) {
    if (!nodes.has(id)) nodes.set(id, {
      hidden: true, textContent: '',
      children: Array.from({length: 5}, () => ({classList: {toggle() {}}})),
    });
    return nodes.get(id);
  },
};
const context = vm.createContext({document, console});
vm.runInContext(source, context);
const call = (expression) => vm.runInContext(expression, context);

test('packet colors and endpoints distinguish forwarding, rate limits, and drops', () => {
  assert.equal(call("packetVisual({ok:true,traffic:'SAFETY',reason:'FORWARDED'}).label"), 'Safety delivered');
  assert.equal(call("packetVisual({ok:true,traffic:'UDP_FLOOD',reason:'FORWARDED'}).label"), 'Flood delivered');
  assert.equal(call("packetVisual({ok:false,traffic:'UDP_FLOOD',reason:'RATE_LIMIT'}).label"), 'Rate-limited');
  assert.equal(call("packetVisual({ok:false,traffic:'UDP_FLOOD',reason:'M2_TEMP_BLOCK'}).label"), 'Dropped');
  assert.equal(call("packetVisual({ok:false,traffic:'UDP_FLOOD',reason:'RATE_LIMIT'}).stop"), .58);
});

test('guided sequence waits for observed stages and a timed recovery', () => {
  const snapshot = {time: 5, vehicles:[{id:'V07',m2_state:'NORMAL'}]};
  context.snapshot = snapshot;
  assert.equal(call("demoTransition('baseline',snapshot,0,'V07')"), 'flood');
  assert.equal(call("demoTransition('flood',snapshot,5,'V07')"), 'flood');
  snapshot.vehicles[0].m2_state = 'METER';
  assert.equal(call("demoTransition('flood',snapshot,5,'V07')"), 'detected');
  snapshot.time = 15; snapshot.vehicles[0].m2_state = 'BLOCK';
  assert.equal(call("demoTransition('detected',snapshot,5,'V07')"), 'mitigated');
  snapshot.time = 18;
  assert.equal(call("demoTransition('mitigated',snapshot,15,'V07')"), 'recovering');
  assert.equal(call("demoTransition('recovering',snapshot,18,'V07')"), 'recovering');
  snapshot.time = 48; snapshot.vehicles[0].m2_state = 'NORMAL';
  assert.equal(call("demoTransition('recovering',snapshot,18,'V07')"), 'complete');
});

test('demo surfaces an unobserved mitigation instead of claiming success', () => {
  context.snapshot = {time: 50, vehicles:[{id:'V07',m2_state:'NORMAL'}]};
  assert.equal(call("demoTransition('flood',snapshot,5,'V07')"), 'stalled');
});

test('handover cue appears only for a recent completed handover', () => {
  context.snapshot = {time: 12, events:[{kind:'HANDOVER',time:11,message:'V07: RSU-1 → RSU-2'}]};
  call('rememberHandovers(snapshot)');
  assert.equal(nodes.get('handoverBanner').hidden, false);
  assert.match(nodes.get('handoverBanner').textContent, /V07: RSU-1 → RSU-2/);
  context.snapshot = {time: 17, events:[]};
  call('rememberHandovers(snapshot)');
  assert.equal(nodes.get('handoverBanner').hidden, true);
});

test('vehicle interpolation is time bounded and follows a right-angle road turn', () => {
  const segment = call('({from:{x:0,y:0,angle:0},to:{x:10,y:10,angle:90},at:100,duration:400,corner:routeCorner({x:0,y:0,angle:0},{x:10,y:10,angle:90})})');
  context.segment = segment;
  assert.equal(call('interpolateVehicle(segment,100).x'), 0);
  assert.equal(call('interpolateVehicle(segment,300).x'), 10);
  assert.equal(call('interpolateVehicle(segment,300).y'), 0);
  assert.equal(call('interpolateVehicle(segment,700).y'), 10);
  assert.equal(call('interpolateVehicle(segment,150,true).y'), 10);
  assert.equal(call('motionDuration(.45,1,true,false)'), 450);
  assert.equal(call('motionDuration(3,1,true,false)'), 650);
  assert.equal(call('motionDuration(.45,1,false,false)'), 0);
  assert.equal(call('motionDuration(.45,1,true,true)'), 0);
  assert.equal(call('motionDuration(0,1,true,false)'), 0);
});

test('map display defaults avoid clutter and every layer has a control', () => {
  assert.equal(call('mapDisplay.associations'), false);
  assert.equal(call('mapDisplay.labels'), false);
  for (const key of ['coverage','associations','packets','labels','attacks','lowEffects']) {
    assert.match(html, new RegExp(`data-map-display="${key}"`));
  }
  call('setMapDisplay("coverage",false);setMapDisplay("packets",false);setMapDisplay("unknown",true)');
  assert.equal(call('mapDisplay.associations'), false);
  assert.equal(call('mapDisplay.packets'), false);
  assert.equal(call('Object.hasOwn(mapDisplay,"unknown")'), false);
});

test('reset cleanup drops old animation and handover state', () => {
  call('animatedCars.set("V01",{x:1});motion.set("V01",{});seenHandovers.add("old");handoverFx={vehicle:"V01"};clearAnimationState()');
  assert.equal(call('animatedCars.size + motion.size + seenHandovers.size'), 0);
  assert.equal(call('handoverFx'), null);
  assert.match(source, /if \(state && newState\.time < state\.time - \.1\) \{\s*clearAnimationState\(\)/);
  assert.match(source, /if \(count >= \(quiet \? 5 : 14\)\) break/);
  assert.match(source, /!mapDisplay\.associations && \(!vehicleInspected \|\| v\.id !== selectedVehicle\)/);
  assert.match(source, /mapDisplay\.lowEffects \|\| reducedMotion\?\.matches \? 100 : 33/);
});
