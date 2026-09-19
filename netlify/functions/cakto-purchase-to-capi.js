// netlify/functions/cakto-purchase-to-capi.js
//
// Recebe o webhook "purchase_approved" da Cakto, monta o user_data
// (com hash SHA-256 na PII) e envia o evento Purchase para a Meta
// Conversions API — resolvendo o problema de EMQ baixo no Purchase.
//
// Variáveis de ambiente necessárias (configure no painel da Netlify em
// Site settings > Environment variables):
//   CAKTO_WEBHOOK_SECRET   -> o "secret" gerado ao criar o webhook na Cakto
//   META_ACCESS_TOKEN      -> token de acesso da Conversions API (Events Manager)
//   META_DATASET_ID        -> (o ID do seu dataset "Dados Cakto")
//   META_TEST_EVENT_CODE   -> opcional, só durante testes (aba "Testar Eventos")

const crypto = require('node:crypto');

const TOLERANCE_SECONDS = 5 * 60; // janela de tolerância pra timestamp do webhook

function sha256(value) {
  return crypto
    .createHash('sha256')
    .update(String(value).trim().toLowerCase())
    .digest('hex');
}

function normalizePhone(phone) {
  // Meta espera telefone só com dígitos, com código do país, sem "+" nem espaços
  return String(phone || '').replace(/\D/g, '');
}

function isFromCakto(rawBody, headers) {
  const secretEnv = process.env.CAKTO_WEBHOOK_SECRET;
  // headers do Netlify Functions vêm com as chaves em minúsculo
  const signatureHeader = headers['x-cakto-signature'];
  const timestampHeader = headers['x-cakto-timestamp'];

  // Preferência: validar pela assinatura HMAC no header
  if (signatureHeader && timestampHeader) {
    const age = Math.abs(Date.now() / 1000 - Number(timestampHeader));
    if (age > TOLERANCE_SECONDS) return false;

    const expected = crypto
      .createHmac('sha256', secretEnv)
      .update(`${timestampHeader}.`)
      .update(rawBody)
      .digest('hex');

    const expectedHeader = `v1=${expected}`;
    const a = Buffer.from(signatureHeader);
    const b = Buffer.from(expectedHeader);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  // Fallback: validar pelo campo "secret" no corpo
  try {
    const parsed = JSON.parse(rawBody);
    const received = parsed.secret || '';
    const a = Buffer.from(received);
    const b = Buffer.from(secretEnv);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  // Netlify pode entregar o corpo em base64 dependendo do content-type;
  // sempre normalize para string crua antes de validar a assinatura.
  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body, 'base64').toString('utf8')
    : event.body;

  if (!isFromCakto(rawBody, event.headers)) {
    return { statusCode: 401, body: 'Unauthorized' };
  }

  const payload = JSON.parse(rawBody);

  if (payload.event !== 'purchase_approved') {
    return { statusCode: 200, body: 'Ignored (not purchase_approved)' };
  }

  const { data } = payload;
  const customer = data.customer || {};
  const address = data.address || {};

  const [firstName, ...rest] = (customer.name || '').trim().split(/\s+/);
  const lastName = rest.join(' ');

  const userData = {
    em: customer.email ? [sha256(customer.email)] : undefined,
    ph: customer.phone ? [sha256(normalizePhone(customer.phone))] : undefined,
    fn: firstName ? [sha256(firstName)] : undefined,
    ln: lastName ? [sha256(lastName)] : undefined,
    ct: address.city ? [sha256(address.city)] : undefined,
    st: address.state ? [sha256(address.state)] : undefined,
    zp: address.zipcode ? [sha256(address.zipcode)] : undefined,
    country: address.country ? [sha256(address.country)] : undefined,
    // fbc/fbp NÃO são hasheados — vão em texto puro
    fbc: data.fbc || undefined,
    fbp: data.fbp || undefined,
  };

  // Remove chaves undefined (Meta não gosta de receber campo vazio)
  Object.keys(userData).forEach((key) => userData[key] === undefined && delete userData[key]);

  const eventTime = data.paidAt
    ? Math.floor(new Date(data.paidAt).getTime() / 1000)
    : Math.floor(Date.now() / 1000);

  const eventPayload = {
    data: [
      {
        event_name: 'Purchase',
        event_time: eventTime,
        event_id: data.id, // mesma chave de dedupe que a Cakto usa (data.id do pedido)
        action_source: 'website',
        event_source_url: data.checkoutUrl || undefined,
        user_data: userData,
        custom_data: {
          currency: data.offer?.currency || 'BRL',
          value: data.amount,
          content_name: data.product?.name,
          content_ids: data.product?.id ? [data.product.id] : undefined,
        },
      },
    ],
  };

  if (process.env.META_TEST_EVENT_CODE) {
    eventPayload.test_event_code = process.env.META_TEST_EVENT_CODE;
  }

  const metaResponse = await fetch(
    `https://graph.facebook.com/v21.0/${process.env.META_DATASET_ID}/events?access_token=${process.env.META_ACCESS_TOKEN}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(eventPayload),
    }
  );

  const metaResult = await metaResponse.json();

  if (!metaResponse.ok) {
    console.error('Erro ao enviar evento para o Meta CAPI:', metaResult);
    return { statusCode: 502, body: JSON.stringify(metaResult) };
  }

  return { statusCode: 200, body: JSON.stringify({ ok: true, meta: metaResult }) };
};
