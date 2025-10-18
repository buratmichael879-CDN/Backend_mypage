/**
 * luftdicht.js
 *
 * Unternehmensgerechte, wartbare und testfreundliche Implementierung eines
 * ISMS (Information Security Management System) "stub"-Moduls.
 *
 * Ziele:
 * - Saubere API (asynchrone Funktionen, konsistente Rückgaben)
 * - Einfache Ersetzbarkeit der Implementationen (config.controls)
 * - Logging- und Audit-Integration (config.logger, config.auditSink)
 * - Validierung der Konfiguration
 * - Export sowohl für CommonJS als auch ES Module
 *
 * Nutzung:
 * const { initISMS } = require('./luftdicht');
 * const isms = initISMS({ logger: myLogger, controls: { manageInformationStorage: async () => { ... } } });
 * await isms.manageInformationStorage();
 * const report = await isms.runAllControls();
 *
 * Hinweis: Dieses Modul implementiert "Kontrollen" als asynchrone Funktionen, die
 * ein standardisiertes Ergebnis-Objekt zurückgeben:
 * { ok: boolean, message: string, name: string, details?: any }
 *
 * Das Modul enthält nur "orchestrierende" Logik — die eigentliche technische
 * Absicherung (z. B. Integrationen, Policies, IAM-Änderungen) muss in den
 * control-Implementierungen vorgenommen werden.
 */

'use strict';

/* ---------- Helpers ---------- */

const DEFAULT_TIMEOUT_MS = 30_000;

function createDefaultLogger() {
  return {
    info: (...args) => console.log('[INFO]', ...args),
    warn: (...args) => console.warn('[WARN]', ...args),
    error: (...args) => console.error('[ERROR]', ...args),
    debug: (...args) => console.debug ? console.debug('[DEBUG]', ...args) : console.log('[DEBUG]', ...args),
  };
}

function safeString(s) {
  return (typeof s === 'string' && s.length > 0) ? s : '';
}

function wrapControl(name, impl, logger) {
  // Ensure impl is async and returns standardized result
  const normalized = (typeof impl === 'function') ? impl : async () => ({ ok: true, message: 'noop' });

  return async (opts = {}) => {
    const meta = { name };
    const start = Date.now();
    try {
      logger.debug(`Start control: ${name}`);
      // allow impl to return boolean, string, or standardized object
      const raw = await Promise.race([
        Promise.resolve(normalized(opts)),
        new Promise((_, rej) => setTimeout(() => rej(new Error('control timeout')), opts.timeoutMs || DEFAULT_TIMEOUT_MS)),
      ]);

      let result;
      if (typeof raw === 'boolean') {
        result = { ok: raw, message: raw ? 'success' : 'failed', name };
      } else if (raw && typeof raw === 'object' && ('ok' in raw)) {
        result = { name, ok: Boolean(raw.ok), message: safeString(raw.message || (raw.ok ? 'success' : 'failed')), details: raw.details };
      } else {
        // unknown return - consider success if truthy
        const ok = Boolean(raw);
        result = { name, ok, message: safeString(raw && raw.message) || (ok ? 'success' : 'failed'), details: raw };
      }

      const duration = Date.now() - start;
      logger.info(`Control ${name} completed`, { ok: result.ok, durationMs: duration, message: result.message });
      return result;
    } catch (err) {
      const duration = Date.now() - start;
      logger.error(`Control ${name} error`, err && err.message ? err.message : err, { durationMs: duration });
      return { name, ok: false, message: err && err.message ? err.message : 'unexpected error', details: err };
    }
  };
}

/* ---------- Standard Control Names & Metadata ---------- */

const STANDARD_CONTROLS = [
  { name: 'enforcePolicies', description: 'Policies einführen und durchsetzen', iso: 'A.5.x' },
  { name: 'defineRoles', description: 'Rollen & Verantwortlichkeiten definieren', iso: 'A.6.x' },
  { name: 'segregateDuties', description: 'Aufgabentrennung sicherstellen', iso: 'A.6.x' },
  { name: 'manageResponsibilities', description: 'Verantwortlichkeiten dokumentieren', iso: 'A.6.x' },
  { name: 'contactWithAuthorities', description: 'Kontakt zu Behörden / CERTs pflegen', iso: 'A.16.x' },
  { name: 'communication', description: 'Sichere Kommunikation etablieren', iso: 'A.13.x' },
  { name: 'preventInformationLeakage', description: 'Maßnahmen gegen Datenabfluss', iso: 'A.8/A.13' },
  { name: 'manageInformationClassification', description: 'Informationsklassifizierung', iso: 'A.8.x' },
  { name: 'labelInformation', description: 'Metadaten / Label auf Informationen anwenden', iso: 'A.8.x' },
  { name: 'manageInformationTransfer', description: 'Sichere Übertragung / Transferkontrollen', iso: 'A.13.x' },
  { name: 'manageInformationMedia', description: 'Handhabung von Datenträgern', iso: 'A.8.x' },
  { name: 'manageInformationStorage', description: 'Speicher- und Backup-Management', iso: 'A.12.x' },
  { name: 'manageInformationAccess', description: 'Zugriffssteuerung (IAM)', iso: 'A.9.x' },
  { name: 'manageInformationUsage', description: 'Zweckbindung & Nutzungskontrolle', iso: 'A.8.x' },
  { name: 'manageInformationRetention', description: 'Aufbewahrungs- und Löschfristen', iso: 'A.8.x' },
  { name: 'manageSupplierRelationships', description: 'Lieferantenmanagement', iso: 'A.15.x' },
  { name: 'manageInformationSecurityInSupplierAgreements', description: 'Sicherheitsanforderungen in Verträgen', iso: 'A.15.x' },
  { name: 'manageInformationSecurityInICTSupplyChain', description: 'Sicherung der ICT-Lieferkette', iso: 'SupplyChain' },
  { name: 'manageInformationSecurityInCloudServices', description: 'Cloud-spezifische Sicherheitsmaßnahmen', iso: 'Cloud' },
  { name: 'manageInformationSecurityForICTReadiness', description: 'Business continuity & ICT-Readiness', iso: 'BCP' },
  { name: 'manageLegalRequirements', description: 'Rechtliche Anforderungen einhalten', iso: 'Legal' },
  { name: 'manageIntellectualPropertyRights', description: 'IPR Schutz', iso: 'Legal' },
  { name: 'manageProtectionOfRecords', description: 'Schutz von Aufzeichnungen', iso: 'A.8.x' },
  { name: 'manageInformationSecurityInProjectManagement', description: 'Sicherheit im Projektmanagement', iso: 'PM' },
  { name: 'manageInformationSecurityInITManagement', description: 'Sicherheit im IT-Management', iso: 'ITSM' },
  { name: 'manageInformationSecurityInOutsourcing', description: 'Sicherheit bei Auslagerung', iso: 'A.15.x' },
  { name: 'manageInformationSecurityInThirdPartyServices', description: 'Drittanbieter-Service Security', iso: 'A.15.x' },
  { name: 'manageInformationSecurityInIoT', description: 'IoT-spezifische Controls', iso: 'IoT' },
  { name: 'manageInformationSecurityInRemoteWorking', description: 'Remote Work & HomeOffice', iso: 'A.6/A.13' },
  { name: 'manageInformationSecurityInTeleworking', description: 'Teleworking-spezifische Controls', iso: 'A.6/A.13' },
  { name: 'manageInformationSecurityInBYOD', description: 'Bring-Your-Own-Device Steuerung', iso: 'A.6/A.13' },
  { name: 'manageInformationSecurityInMobileDevices', description: 'Mobile Endgeräte Sicherheit', iso: 'A.6/A.13' },
  { name: 'manageInformationSecurityInEndpointDevices', description: 'Endpoint-Schutz', iso: 'A.12/A.13' },
  { name: 'manageInformationSecurityInUserEndpointDevices', description: 'Benutzerendgeräte Management', iso: 'A.12' },
  { name: 'manageInformationSecurityInPhysicalSecurity', description: 'Physische Sicherheitsmaßnahmen', iso: 'A.11.x' },
  { name: 'manageInformationSecurityInEnvironmentalControls', description: 'Umwelt- und Infrastrukturkontrollen', iso: 'A.11.x' },

  // People Controls
  { name: 'screenPersonnel', description: 'Personalüberprüfung / Background-Checks', iso: 'A.7.x' },
  { name: 'manageTermsAndConditions', description: 'AGB / Verträge / Aushänge für Mitarbeiter', iso: 'HR' },
  { name: 'manageInformationSecurityAwareness', description: 'Security Awareness & Training', iso: 'A.7.x' },
];

/* ---------- Module / Factory ---------- */

function initISMS(config = {}) {
  const logger = (config && config.logger) ? config.logger : createDefaultLogger();
  const auditSink = config && config.auditSink; // optional function(result) to store audit events
  const controlsImpl = config && config.controls ? config.controls : {};

  // validate basic config shape
  if (config && typeof config !== 'object') {
    throw new TypeError('config must be an object');
  }
  if (auditSink && typeof auditSink !== 'function') {
    throw new TypeError('auditSink must be a function if provided');
  }

  // Build control functions (wrapped)
  const controls = {};
  for (const meta of STANDARD_CONTROLS) {
    const impl = controlsImpl[meta.name] || (async (opts = {}) => {
      // Default implementation: log and return ok
      logger.debug(`Default impl for ${meta.name} executed. Provide a custom implementation via config.controls.${meta.name} for real checks.`);
      return { ok: true, message: `Default stub executed for ${meta.name}`, details: { iso: meta.iso, description: meta.description } };
    });

    controls[meta.name] = wrapControl(meta.name, impl, logger);
  }

  // Additional utility methods
  async function runAllControls(options = {}) {
    logger.info('Running all ISMS controls');
    const controlNames = Object.keys(controls);
    const results = [];
    for (const n of controlNames) {
      // each control gets the same options by default, can pass per-control via options.perControl
      const perControlOpts = Object.assign({}, options, (options.perControl && options.perControl[n]) ? options.perControl[n] : {});
      const res = await controls[n](perControlOpts);
      results.push(res);
      if (auditSink) {
        try { await Promise.resolve(auditSink(res)); } catch (e) { logger.warn('auditSink failed for control', n, e && e.message ? e.message : e); }
      }
    }
    return results;
  }

  function getControlNames() {
    return Object.keys(controls);
  }

  function setLogger(newLogger) {
    if (!newLogger || typeof newLogger.info !== 'function') throw new TypeError('logger must implement info/debug/warn/error');
    // Note: this only replaces logger reference for future wrappers; existing wrappers keep their logger.
    // For full replacement, re-init or set per-control impls again.
    config.logger = newLogger;
    logger.info && logger.info('Logger replaced for ISMS factory (note: existing wrapped controls keep old logger)');
    return true;
  }

  function setControlImplementation(name, impl) {
    if (!name || typeof name !== 'string') throw new TypeError('name required');
    if (typeof impl !== 'function') throw new TypeError('impl must be a function');
    if (!STANDARD_CONTROLS.find(c => c.name === name)) {
      throw new Error(`Unknown control name: ${name}`);
    }
    // replace control with wrapped impl bound to current logger
    controls[name] = wrapControl(name, impl, logger);
    logger.info(`Control implementation replaced: ${name}`);
    return true;
  }

  async function auditReport() {
    // lightweight aggregated report
    const results = await runAllControls({ timeoutMs: config.defaultTimeoutMs || DEFAULT_TIMEOUT_MS });
    const summary = {
      timestamp: new Date().toISOString(),
      ok: results.every(r => r.ok),
      total: results.length,
      passing: results.filter(r => r.ok).length,
      failing: results.filter(r => !r.ok).length,
      details: results,
    };
    return summary;
  }

  // Public API: expose control functions individually + utilities
  const api = {
    // spread controls (dynamic)
    ...controls,

    // utilities
    runAllControls,
    getControlNames,
    setLogger,
    setControlImplementation,
    auditReport,

    // metadata
    _meta: {
      createdAt: new Date().toISOString(),
      standardControls: STANDARD_CONTROLS.slice(),
      configSnapshot: () => ({ defaultTimeoutMs: config.defaultTimeoutMs || DEFAULT_TIMEOUT_MS, hasAuditSink: Boolean(auditSink) }),
    },
  };

  // freeze API surface for safety in production
  return Object.freeze(api);
}

/* CommonJS and ES module exports */
module.exports = { initISMS };
module.exports.default = initISMS;
export default initISMS;
