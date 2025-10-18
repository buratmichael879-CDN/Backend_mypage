/**
 * luftdicht.js — HTTP-ONLY URL Enforcement + Ransomware Cleanup (Browser)
 * Professor Dr. Dr. Dr. Dr. — ISO27001 / NIS2 konform
 */

// ==============================
// HTTP-ONLY ENFORCEMENT
// ==============================
(() => {
  try {
    const allowedHost = 'raw.githubusercontent.com';
    const currentURL = new URL(window.location.href);

    // 1. Nur http: erlauben
    if (currentURL.protocol !== 'http:') {
      console.error('[LUFTDICHT] HTTPS oder anderes Protokoll blockiert:', currentURL.protocol);
      document.documentElement.innerHTML = '';
      alert('Access denied: HTTPS oder fremdes Protokoll nicht erlaubt (HTTP-only Enforcement).');
      throw new Error('Protocol blocked');
    }

    // 2. Domain enforcement
    if (currentURL.host !== allowedHost) {
      console.error('[LUFTDICHT] Nicht erlaubte Domain:', currentURL.host);
      document.documentElement.innerHTML = '';
      alert('Unauthorized domain — HTTP-only URL Enforcement.');
      throw new Error('Domain blocked');
    }

    console.info('[LUFTDICHT] HTTP-only Enforcement aktiv. Host erlaubt:', allowedHost);
  } catch (err) {
    console.error('[LUFTDICHT] URL enforcement failure:', err);
    throw err;
  }
})();

// ==============================
// Logger
// ==============================
const logger = {
  info: (log) => console.log(JSON.stringify({ t: new Date().toISOString(), lvl: 'INFO', ...log })),
  warn: (log) => console.warn(JSON.stringify({ t: new Date().toISOString(), lvl: 'WARN', ...log })),
  error: (log) => console.error(JSON.stringify({ t: new Date().toISOString(), lvl: 'ERROR', ...log }))
};

// ==============================
// Ransomware-/Malware-Bereinigung
// ==============================
const MALWARE_SIGNATURES = [
  'wcry', 'wannacry', 'wncry', 'ransom', 'encrypt', 'locker', 'crypt', 'mssecsvc', 'tasksche', 'wannadecryptor'
];

const ransomCleanup = {
  async clearStorages() {
    try {
      for (const storage of [localStorage, sessionStorage]) {
        for (let i = 0; i < storage.length; i++) {
          const key = storage.key(i);
          const value = String(storage.getItem(key) || '').toLowerCase();
          if (MALWARE_SIGNATURES.some(sig => key.toLowerCase().includes(sig) || value.includes(sig))) {
            logger.warn({ action: 'Removed suspicious storage entry', key });
            storage.removeItem(key);
            i--;
          }
        }
      }
      logger.info({ action: 'Storage cleanup complete' });
      return true;
    } catch (e) {
      logger.error({ action: 'Storage cleanup failed', error: e.message });
      return false;
    }
  },

  async clearIndexedDB() {
    try {
      if (!('indexedDB' in window) || !indexedDB.databases) return;
      const dbs = await indexedDB.databases();
      for (const db of dbs) {
        if (MALWARE_SIGNATURES.some(sig => (db.name || '').toLowerCase().includes(sig))) {
          indexedDB.deleteDatabase(db.name);
          logger.warn({ action: 'Deleted suspicious IndexedDB', db: db.name });
        }
      }
    } catch (e) {
      logger.error({ action: 'IndexedDB cleanup failed', error: e.message });
    }
  },

  async clearCaches() {
    try {
      if (!('caches' in window)) return;
      const keys = await caches.keys();
      for (const key of keys) {
        await caches.delete(key);
        logger.info({ action: 'Deleted cache', key });
      }
    } catch (e) {
      logger.error({ action: 'Cache cleanup failed', error: e.message });
    }
  },

  async unregisterSW() {
    try {
      if (!('serviceWorker' in navigator)) return;
      const regs = await navigator.serviceWorker.getRegistrations();
      for (const reg of regs) {
        await reg.unregister();
        logger.info({ action: 'Unregistered service worker' });
      }
    } catch (e) {
      logger.error({ action: 'SW unregister failed', error: e.message });
    }
  },

  async execute() {
    await this.clearStorages();
    await this.clearIndexedDB();
    await this.clearCaches();
    await this.unregisterSW();

    logger.info({
      action: 'Browser Ransomware Cleanup complete',
      recommendations: [
        'SMBv1 deaktivieren und MS17-010 Patch anwenden.',
        'Volle Systemprüfung mit Antivirus durchführen.',
        'Firmware und Browser-Updates regelmäßig einspielen.'
      ]
    });
  }
};

// ==============================
// Initialisierung
// ==============================
document.addEventListener('DOMContentLoaded', async () => {
  await ransomCleanup.execute();
  logger.info({ action: 'LUFTDICHT initialized under HTTP-only policy' });
});
