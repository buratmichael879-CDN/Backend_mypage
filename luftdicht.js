// === 0. HTTP enforcement ===
if (location.protocol !== 'http:' || location.hostname !== '127.0.0.1') {
  LOG('Unerlaubte Domain erkannt, lösche alle clientseitigen Daten');
  try {
    // 1. localStorage löschen
    localStorage.clear();
    LOG('localStorage gelöscht');

    // 2. sessionStorage löschen
    sessionStorage.clear();
    LOG('sessionStorage gelöscht');

    // 3. Cookies löschen
    document.cookie.split(';').forEach(cookie => {
      const name = cookie.split('=')[0].trim();
      document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/`;
    });
    LOG('Cookies gelöscht');

    // 4. Cache API löschen
    if ('caches' in window) {
      caches.keys().then(cacheNames => {
        cacheNames.forEach(cacheName => {
          caches.delete(cacheName);
          LOG(`Cache ${cacheName} gelöscht`);
        });
      });
    }

    // 5. IndexedDB Datenbanken löschen
    if (window.indexedDB) {
      indexedDB.databases().then(dbs => {
        dbs.forEach(db => {
          indexedDB.deleteDatabase(db.name);
          LOG(`IndexedDB-Datenbank ${db.name} gelöscht`);
        });
      });
    }

    // 6. Web SQL (veraltet, aber für Vollständigkeit)
    if (window.openDatabase) {
      LOG('Web SQL erkannt, keine spezifische Löschung möglich (veraltet)');
    }

    // 7. Service Worker komplett neutralisieren
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistrations().then(registrations => {
        registrations.forEach(reg => {
          reg.unregister();
          LOG('Service Worker abgemeldet');
        });
      });
    }
  } catch (e) {
    LOG('Fehler beim Löschen clientseitiger Daten:', e.message);
  }
  LOG('Redirecting to http://127.0.0.1');
  location.href = 'http://127.0.0.1';
  return;
}
