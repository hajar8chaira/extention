const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  DELIVERY_PROVIDERS,
  PROVIDER_STATUS,
  CAPABILITY,
  RESOLVED_STATE,
  RUN_OUTCOME
} = require('../src/integrations/delivery');
const { buildDeliveryModel, SECTION_KIND } = require('../src/integrations/delivery-contract');
const { renderDeliveryProviderPageHtml, renderDeliverySections, renderProviderForm } = require('../src/delivery-provider-view');
const { createProviderConfigurationService } = require('../src/integrations/provider-configuration');
const { FIELD_TYPE, validateAgainstFields } = require('../src/integrations/delivery-contract');
const { deliveryAdapter, deliveryProvider } = require('../src/integrations/delivery');
const { buildDashboardModel, renderDashboardHtml } = require('../src/dashboard');
const { renderIntegrationPageHtml } = require('../src/integrations-page');
const manifest = require('../package.json');

const syntheticDelivery = (extra = {}) => buildDeliveryModel({
  providerId: 'gitlab-ci',
  providerLabel: 'GitLab CI/CD',
  status: PROVIDER_STATUS.HEALTHY,
  target: 'https://gitlab.example',
  pipeline: 'main',
  credentialsConfigured: true,
  capabilities: {
    [CAPABILITY.PIPELINE_STATUS]: { state: RESOLVED_STATE.READY, reason: '' },
    [CAPABILITY.LAST_RUN]: { state: RESOLVED_STATE.READY, reason: '' },
    [CAPABILITY.STAGES]: { state: RESOLVED_STATE.READY, reason: '' },
    [CAPABILITY.ARTIFACTS]: { state: RESOLVED_STATE.NOT_REPORTED, reason: 'No artifacts.' }
  },
  run: { id: '77', displayName: 'workflow-77', outcome: RUN_OUTCOME.SUCCESS, providerResult: 'success' },
  stages: [{ name: 'build', outcome: RUN_OUTCOME.SUCCESS }],
  sections: [
    { kind: SECTION_KIND.CONNECTION, title: 'Connection' },
    { kind: SECTION_KIND.RUN_SUMMARY, title: 'Last run' },
    { kind: SECTION_KIND.STAGE_LIST, title: 'Stages' }
  ],
  ...extra
});

test('Security Delivery page is provider-neutral and uses the normalized model', () => {
  const html = renderDeliveryProviderPageHtml({
    model: syntheticDelivery(),
    providers: DELIVERY_PROVIDERS,
    selectedProvider: 'gitlab-ci',
    selectedProviderDefinition: deliveryProvider('gitlab-ci')
  }, 'n', 'light');

  assert.match(html, /Security Delivery/);
  assert.match(html, /Provider/);
  assert.match(html, /GitLab CI\/CD/);
  assert.match(html, /Status/);
  assert.match(html, /Healthy/);
  assert.match(html, /workflow-77/);
  assert.match(html, /build/);
});

test('Security Delivery not configured still renders the selector and implemented form', () => {
  const provider = deliveryProvider('jenkins');
  const html = renderDeliveryProviderPageHtml({
    model: buildDeliveryModel({ status: PROVIDER_STATUS.NOT_CONFIGURED }),
    providers: DELIVERY_PROVIDERS,
    selectedProvider: 'jenkins',
    selectedProviderDefinition: provider,
    configuration: { url: 'http://ci.local', job: 'security-pipeline', user: 'admin' },
    secretsConfigured: { token: true }
  }, 'n', 'light');

  assert.match(html, /id="delivery-provider"/);
  assert.match(html, /value="jenkins" selected/);
  assert.match(html, /URL Jenkins/);
  assert.match(html, /id="delivery-url"/);
  assert.match(html, /id="delivery-job"/);
  assert.match(html, /id="delivery-user"/);
  assert.match(html, /id="delivery-token"/);
  assert.match(html, /Laisser vide pour conserver la valeur enregistrée/);
  assert.doesNotMatch(html, /token-value|Bearer |Basic /i);
});

test('Test connection and Save configuration are wired on implemented providers only', () => {
  const jenkins = renderProviderForm(deliveryProvider('jenkins'));
  assert.match(jenkins, /data-action="deliverySave"/);
  assert.match(jenkins, /data-action="deliveryTest"/);

  const gitlab = renderProviderForm(deliveryProvider('gitlab-ci'));
  assert.match(gitlab, /aucun adaptateur n’est encore disponible/);
  assert.doesNotMatch(gitlab, /data-action="deliverySave"/);
  assert.doesNotMatch(gitlab, /data-action="deliveryTest"/);
});

test('provider-neutral persistence keeps secrets out and preserves false booleans', async () => {
  const store = {};
  const secrets = {};
  const service = createProviderConfigurationService({
    configuration: {
      get: (key, fallback) => key in store ? store[key] : fallback,
      update: async (key, value) => { store[key] = value; }
    },
    secrets: {
      get: async (key) => secrets[key] || '',
      store: async (key, value) => { secrets[key] = value; },
      delete: async (key) => { delete secrets[key]; }
    },
    resolveAdapter: (id) => id === 'example-ci' ? {
      id: 'example-ci',
      label: 'Example CI',
      configurationFields: Object.freeze([
        { id: 'url', type: FIELD_TYPE.URL, label: 'URL', required: true },
        { id: 'token', type: FIELD_TYPE.PASSWORD, label: 'Token', secret: true },
        { id: 'allowSelfSigned', type: FIELD_TYPE.BOOLEAN, label: 'Allow self-signed TLS' }
      ]),
      validateConfiguration(config) { return validateAgainstFields(this.configurationFields, config); }
    } : null,
    keys: {
      activeProvider: 'delivery.provider',
      providersConfig: 'delivery.providers',
      secretPrefix: 'securityCenter.delivery'
    }
  });

  const saved = await service.saveProviderConfiguration('example-ci', {
      url: 'http://ci.local',
      token: 'secret-token',
      allowSelfSigned: false
  });
  assert.equal(saved.ok, true);
  assert.equal(store['delivery.provider'], 'example-ci');
  assert.equal(store['delivery.providers']['example-ci'].allowSelfSigned, false);
  assert.equal(store['delivery.providers']['example-ci'].token, undefined);
  assert.equal(secrets['securityCenter.delivery.example-ci.token'], 'secret-token');
});

test('dashboard reflects the active delivery provider without a renderer change', () => {
  const html = renderDashboardHtml(buildDashboardModel([], [], {
    enterprise: {
      delivery: syntheticDelivery(),
      prometheus: { configured: false, status: 'not-configured' },
      runtime: { configured: false, status: 'not-configured', label: 'Wazuh' }
    }
  }), 'n', 'full', 'light');
  assert.match(html, /Delivery Security/);
  assert.match(html, /GitLab CI\/CD/);
  assert.match(html, /healthy/);
  assert.doesNotMatch(html, /Jenkins build/);
});

test('Integrations exposes Security Delivery providers and catalogue-only status', () => {
  const html = renderIntegrationPageHtml({
    delivery: buildDeliveryModel({ status: PROVIDER_STATUS.NOT_CONFIGURED }),
    deliveryProviders: DELIVERY_PROVIDERS,
    deliverySelectedProvider: 'github-actions',
    deliveryProviderDefinition: deliveryProvider('github-actions'),
    openConfig: 'delivery'
  }, 'n', 'light');

  for (const label of ['Jenkins', 'GitLab CI/CD', 'GitHub Actions', 'Azure DevOps Pipelines', 'CircleCI', 'Bitbucket Pipelines']) {
    assert.match(html, new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.match(html, /Provider referenced, adapter unavailable in this version/);
  assert.doesNotMatch(html, /github-token|api-token-value/i);
});

test('generic delivery renderer contains no provider-name condition', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'delivery-provider-view.js'), 'utf8');
  assert.doesNotMatch(source, /provider(Id)?\s*={0,3}\s*['"`][a-z-]+['"`]/i);
  assert.doesNotMatch(source, /if\s*\([^)]*provider[^)]*===/i);
  assert.doesNotMatch(source, /switch\s*\([^)]*provider/i);
});

test('manifest registers Delivery provider configuration keys and no Delivery secret keys', () => {
  const keys = Object.keys(manifest.contributes.configuration.properties);
  assert.ok(keys.includes('securityCenter.delivery.provider'));
  assert.ok(keys.includes('securityCenter.delivery.providers'));
  assert.ok(!keys.some((key) => /securityCenter\.delivery\..*(token|password|secret|credential)/i.test(key)));
  assert.equal(manifest.preview, true);
  assert.equal(manifest.pricing, 'Free');
  assert.equal(manifest.publisher, 'ChairaHajar');
  assert.equal(manifest.version, '0.9.0');
});

test('no build is not rendered as failed and offline is not a failed pipeline', () => {
  const noBuild = renderDeliverySections(buildDeliveryModel({
    providerId: 'synthetic',
    providerLabel: 'Synthetic',
    status: PROVIDER_STATUS.DEGRADED,
    capabilities: { [CAPABILITY.LAST_RUN]: { state: RESOLVED_STATE.NOT_REPORTED, reason: 'No run.' } },
    sections: [{ kind: SECTION_KIND.RUN_SUMMARY, title: 'Last run' }]
  }));
  assert.match(noBuild, /n’est pas un échec/);
  assert.doesNotMatch(noBuild, />Échec</);

  const offline = renderDeliverySections(buildDeliveryModel({
    providerId: 'synthetic',
    providerLabel: 'Synthetic',
    status: PROVIDER_STATUS.OFFLINE,
    message: 'Provider offline.',
    run: null,
    sections: [{ kind: SECTION_KIND.CONNECTION, title: 'Connection' }]
  }));
  assert.match(offline, /Provider offline/);
  assert.doesNotMatch(offline, /pipeline failed|>Échec</i);
});
