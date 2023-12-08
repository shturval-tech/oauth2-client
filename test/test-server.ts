import { Application, Middleware, Request } from '@curveball/core';
import bodyParser from '@curveball/bodyparser';
import * as http from 'http';

type TestServer = {
  server: http.Server;
  app: Application;
  lastRequest: () => Request;
  port: number;
  url: string;
  close: () => Promise<void>;
}

let serverCache: null|TestServer = null;

export function testServer() {

  if (serverCache) return serverCache;

  let lastRequest: any = null;

  const app = new Application();

  app.use(bodyParser());
  app.use((ctx, next) => {
    lastRequest = ctx.request;
    return next();
  });
  app.use(issueToken);
  app.use(openIdConfig);
  const port = 40000 + Math.round(Math.random()*9999);
  const server = app.listen(port);

  serverCache = {
    server,
    app,
    lastRequest: (): Request => lastRequest,
    port,
    url: 'http://localhost:' + port,
    close: async() => {

      return new Promise<void>(res => {
        server.close(() => res());
      });

    }

  };
  return serverCache;

}

const issueToken: Middleware = (ctx, next) => {

  if (ctx.path !== '/token') {
    return next();
  }

  ctx.response.type = 'application/json';
  ctx.response.body = {
    access_token: 'access_token_000',
    refresh_token: 'refresh_token_000',
    expires_in: 3600,
  };

};

const openIdConfig: Middleware = (ctx, next) => {

  if (ctx.path !== '/.well-known/openid-configuration') {
    return next();
  }

  ctx.response.type = 'application/json';
  ctx.response.body = {
    issuer: 'http://localhost:8080',
    token_endpoint: 'http://localhost:8080/testtoken',
    authorization_endpoint: 'http://localhost:8080/testauthorize',
    userinfo_endpoint: 'http://localhost:8080/testuserinfo',
    token_endpoint_auth_methods_supported: ['none'],
    jwks_uri: 'http://localhost:8080/jwks',
    response_types_supported: ['code'],
    grant_types_supported: ['client_credentials', 'authorization_code', 'password'],
    token_endpoint_auth_signing_alg_values_supported: ['RS256'],
    response_modes_supported: ['query'],
    id_token_signing_alg_values_supported: ['RS256'],
    revocation_endpoint: 'http://localhost:8080/testrevoke',
    subject_types_supported: ['public'],
    end_session_endpoint: 'http://localhost:8080/testendsession',
    introspection_endpoint: 'http://localhost:8080/testintrospect',
  };

};
