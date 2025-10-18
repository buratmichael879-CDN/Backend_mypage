/* luftdicht.js — Complete Browser Isolation + Payment Leak Closure
   Professor Dr. Dr. Dr. Dr. — ISO27001 / NIS2 Version
   Features:
   - HTTP-only enforcement (127.0.0.1)
   - Camera, mic, geo, sensors, WebRTC, USB, Bluetooth, push, notifications blocked
   - Payment & autofill leaks closed (5 protection functions)
   - Permissions-Policy injection (no CSP)
   - Background watchdog + service worker neutralizer
*/

(function Luftdicht(window, document){
  'use strict';
  const LOG = (...a)=>console.log('[LUFTDICHT]',...a);
  const now = ()=>new Date().toISOString();

  // === 0. HTTP enforcement ===
  if(location.protocol!=='http:' || location.hostname!=='127.0.0.1'){
    LOG('Redirecting to http://127.0.0.1');
    location.href='http://127.0.0.1';
    return;
  }

  // === 1. Permissions-Policy Injection (no CSP) ===
  (function injectPermissions(){
    const meta=document.createElement('meta');
    meta.name='permissions-policy';
    meta.content='camera=(), microphone=(), geolocation=(), payment=(), interest-cohort=()';
    document.head.prepend(meta);
    LOG('Permissions-Policy applied');
  })();

  // === 2. Privacy Protection Core ===
  (function privacy(){
    // Camera / Mic
    if(navigator.mediaDevices){
      navigator.mediaDevices.getUserMedia=()=>Promise.reject(new DOMException('Blocked','NotAllowedError'));
      navigator.mediaDevices.enumerateDevices=()=>Promise.resolve([]);
    }
    // Geo
    if(navigator.geolocation){
      navigator.geolocation.getCurrentPosition=(s,e)=>e&&e({code:1,message:'Blocked'});
