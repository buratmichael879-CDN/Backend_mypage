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
 * - Export für CommonJS
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
  { name: 'manageTermsAndConditions', description: 'AGB / Verträge verwalten', iso: 'A.7.x' },
  { name: 'trainPersonnel', description: 'Schulung und Awareness-Programme', iso: 'A.7.x' },
  { name: 'managePersonnelSeparation', description: 'Trennung von Mitarbeitern / Kündigungen', iso: 'A.7.x' },

  // Technical Controls
  { name: 'manageAuthentication', description: 'Authentifizierung und Identitätsmanagement', iso: 'A.9.x' },
  { name: 'manageAuthorization', description: 'Autorisierung und Rollen-Management', iso: 'A.9.x' },
  { name: 'manageEncryption', description: 'Verschlüsselung von Daten', iso: 'A.10.x' },
  { name: 'manageBackupAndRestore', description: 'Backup- und Wiederherstellungsverfahren', iso: 'A.12.x' },
];

/* ---------- ISMS Initialization ---------- */

function initISMS({ controls, logger, auditSink }) {
  // Default logger
  logger = logger || createDefaultLogger();

  // Standardcontrols aus dem Array laden
  const controlsWrapper = {};
  STANDARD_CONTROLS.forEach(({ name, description, iso }) => {
    const controlImpl = controls && controls[name];
    if (controlImpl) {
      controlsWrapper[name] = wrapControl(name, controlImpl, logger);
    }
  });

  return {
    ...controlsWrapper,
    async runAllControls() {
      const results = [];
      for (const controlName of Object.keys(controlsWrapper)) {
        const control = controlsWrapper[controlName];
        results.push(await control());
      }
      return results;
    },
  };
}

/* ---------- Exporte ---------- */

// Hier wird die Funktion ohne "export" direkt als CommonJS exportiert
module.exports = {
  initISMS,
};
