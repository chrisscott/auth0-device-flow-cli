const qrcode = require('qrcode-terminal');
const { red, bold, italic } = require('chalk');
const got = require('got');
const { Issuer } = require('openid-client');

if (!process.env.AUTH0_DOMAIN || !process.env.AUTH0_AUDIENCE) {
  throw new Error('AUTH0_DOMAIN and AUTH0_AUDIENCE must be defined in your environment')
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const { log, error } = console;
const grant_type = 'urn:ietf:params:oauth:grant-type:device_code';
const { 
  ISSUER = `https://${AUTH0_DOMAIN}`, 
  CLIENT_ID = AUTH0_DOMAIN, 
  SCOPE = AUTH0_SCOPE || 'openid email offline_access', 
  AUDIENCE = AUTH0_AUDIENCE
} = process.env;


(async () => {
  log(italic('Starting...'));
  const issuer = await Issuer.discover(ISSUER);
  const client = new issuer.Client({
    client_id: CLIENT_ID,
    token_endpoint_auth_method: 'none',
  });

  const { device_authorization_endpoint } = issuer.metadata;

  let request = { client_id: CLIENT_ID, scope: SCOPE, audience: AUDIENCE, max_age: 300 };
  if (SCOPE.includes('offline_access')) {
    request.prompt = 'consent';
  }

  const response = await got.post(device_authorization_endpoint, { json: request }).json();

  log(`Open ${bold(response.verification_uri)} and enter`);
  log('\n\n');
  log(`=======>       ${bold(response.user_code.split('').join(' '))}       <=======`)
  log(italic('note: you may omit whitespace and special characters'));
  log(italic('      like dashes. You may also enter lowercase.'));
  log('\n\nor scan this code with your Camera app to skip entering the code');
  qrcode.generate(response.verification_uri_complete, { small: true });
  log(italic('note: this code expires in %d minutes'), response.expires_in / 60);

  request = {
    grant_type,
    client_id: CLIENT_ID,
    device_code: response.device_code,
  };

  log(bold(italic('\n\nDevice is starting to poll for results every 5 seconds')));

  let done;
  let tokenset;

  while (!done && !tokenset) {
    tokenset = await client.grant({
      grant_type,
      device_code: response.device_code,
    }).catch((err) => {
      switch (err.error) {
        case 'authorization_pending':
          log(italic('End-User authorization Pending ...'));
          return wait(5000);
        case 'access_denied':
          log(red(bold(italic('End-User cancelled the flow'))));
          done = true;
          break;
        case 'expired_token':
          log(red(bold(italic('The flow has expired'))));
          done = true;
          break;
        default:
          if (err.name === 'OpenIdConnectError') {
            log(red(bold(italic(`error = ${err.error}; error_description = ${err.error_description}`))));
            done = true;
          } else {
            throw err;
          }
      }
    });
  }

  if (tokenset) {
    log(bold('\n\nSuccessful Token Response'))
    log('\nAccess Token:\n')
    log(tokenset.access_token)
  }
})().catch((err) => {
  error(err);
  process.exit(1);
})
