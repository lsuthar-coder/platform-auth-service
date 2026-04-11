// src/tracing.js
// OTel auto-instrumentation — loaded first via -r flag.
'use strict';

const { NodeSDK }           = require('@opentelemetry/sdk-node');
const { getNodeAutoInstrumentations } = require('@opentelemetry/auto-instrumentations-node');
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http');

if (!process.env.OTLP_ENDPOINT) {
  console.log('OTLP_ENDPOINT not set — tracing disabled');
} else {
  const exporter = new OTLPTraceExporter({
    url: process.env.OTLP_ENDPOINT,
    headers: {
      Authorization: 'Basic ' + Buffer.from(
        `${process.env.OTLP_USERNAME}:${process.env.OTLP_PASSWORD}`
      ).toString('base64'),
    },
  });

  const sdk = new NodeSDK({
    serviceName:    process.env.SERVICE_NAME || 'auth-service',
    traceExporter:  exporter,
    instrumentations: [
      getNodeAutoInstrumentations({
        '@opentelemetry/instrumentation-http': {
          ignoreIncomingRequestHook: (req) =>
            req.url === '/health' || req.url === '/metrics',
        },
      }),
    ],
  });

  sdk.start();
  console.log('OpenTelemetry tracing started');
  process.on('SIGTERM', () => sdk.shutdown());
}
