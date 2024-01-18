import { OAuth2Token } from './token';
import {
  AuthorizationCodeRequest,
  ClientCredentialsRequest,
  EndSessionRequest,
  IntrospectionRequest,
  IntrospectionResponse,
  PasswordRequest,
  RefreshRequest,
  TokenResponse,
} from './messages';
import { OAuth2Error } from './error';
import { OAuth2AuthorizationCodeClient } from './client/authorization-code';

const ENDPOINTS = {
  tokenEndpoint: 'token_endpoint',
  authorizationEndpoint: 'authorization_endpoint',
  userinfoEndpoint: 'userinfo_endpoint',
  revocationEndpoint: 'revocation_endpoint',
  endSessionEndpoint: 'end_session_endpoint',
  introspectionEndpoint: 'introspection_endpoint',
  discoveryEndpoint: 'discovery_endpoint',
};

const DEFAULT_LINKS = {
  token_endpoint: '/token',
  authorization_endpoint:  '/authorize',
  userinfo_endpoint:  '/userinfo',
  revocation_endpoint:  '/revoke',
  end_session_endpoint:  '/endsession',
  introspection_endpoint:  '/introspect',
  discovery_endpoint:  '/.well-known/openid-configuration',
};

export interface ClientSettings {

  /**
   * The hostname of the OAuth2 server.
   * If provided, we'll attempt to discover all the other related endpoints.
   *
   * If this is not desired, just specify the other endpoints manually.
   *
   * This url will also be used as the base URL for all other urls. This lets
   * you specify all the other urls as relative.
   */
  server?: string;

  /**
   * OAuth2 clientId
   */
  clientId: string;

  /**
   * OAuth2 clientSecret
   *
   * This is required when using the 'client_secret_basic' authenticationMethod
   * for the client_credentials and password flows, but not authorization_code
   * or implicit.
   */
  clientSecret?: string;

  /**
   * The /authorize endpoint.
   *
   * Required only for the browser-portion of the authorization_code flow.
   */
  authorizationEndpoint?: string;

  /**
   * The token endpoint.
   *
   * Required for most grant types and refreshing tokens.
   */
  tokenEndpoint?: string;

  /**
   * Introspection endpoint.
   *
   * Required for, well, introspecting tokens.
   * If not provided we'll try to discover it, or otherwise default to /introspect
   */
  introspectionEndpoint?: string;

  /**
   * OpenID Authorization Server Metadata endpoint
   * Connect Discovery 1.0 endpoint.
   *
   * If this endpoint is provided it can be used to automatically figure
   * out all the other endpoints.
   *
   * Usually the URL for this is: https://server/.well-known/openid-configuration
   */
  discoveryEndpoint?: string;

  /**
   * OpenID UserInfo Endpoint
   *
   * Protected Resource that returns Claims about the authenticated End-User
   *
   * Usually the URL for this is: https://server/userinfo
   */
  userinfoEndpoint?: string;

  /**
   * OAuth 2.0 Token Revocation Endpoint
   *
   * Revokes an obtained refresh or access token, plus all other tokens linked to the same authorisation grant.
   *
   * Usually the URL for this is: https://server/revoke
   */
  revocationEndpoint?: string;

  /**
   * OpenID Logout Endpoint
   *
   * URL at the OP to which an RP can perform a redirect to request that the End-User be logged out at the OP
   *
   * Usually the URL for this is: https://server/endsession
   */
  endSessionEndpoint?: string;

  /**
   * Fetch implementation to use.
   *
   * Set this if you wish to explicitly set the fetch implementation, e.g. to
   * implement middlewares or set custom headers.
   */
  fetch?: typeof fetch;

  /**
   * Client authentication method that is used to authenticate
   * when using the token endpoint.
   *
   * Can be one of 'client_secret_basic' | 'client_secret_post' | 'client_bearer_header'.
   *
   * The default value is 'client_secret_basic' if not provided.
   */
  authenticationMethod?: string;

  /**
   * The credentials read-only property of the Request interface indicates whether the user agent should send or receive cookies from the other domain in the case of cross-origin requests.
   * https://developer.mozilla.org/en-US/docs/Web/API/Request/credentials
   */
  credentials?: 'omit' | 'same-origin' | 'include';
}


type OAuth2Endpoint =  keyof typeof ENDPOINTS;
type OAuth2EndpointKey =  keyof typeof DEFAULT_LINKS;

export class OAuth2Client {

  settings: ClientSettings;

  constructor(clientSettings: ClientSettings) {
    if(!clientSettings.server) {
      throw new Error(`Server is not specified.`);
    }
    const endpointKeys =  Object.keys(ENDPOINTS);
    const defaultSettings = {};
    for (const key of endpointKeys) {
      const endpointKey = ENDPOINTS[key as OAuth2Endpoint] as OAuth2EndpointKey;
      // @ts-ignore
      defaultSettings[key as OAuth2Endpoint] = resolve( DEFAULT_LINKS[endpointKey] as string, clientSettings.server);
      if( clientSettings[key as OAuth2Endpoint]) {
        clientSettings[key as OAuth2Endpoint] = resolve(clientSettings[key as OAuth2Endpoint] as string, clientSettings.server);
      }
    }


    if (!clientSettings?.fetch) {
      clientSettings.fetch = fetch.bind(globalThis);
    }

    this.settings = {...defaultSettings, ...clientSettings};

  }

  /**
   * Refreshes an existing token, and returns a new one.
   */
  async refreshToken(token: OAuth2Token): Promise<OAuth2Token> {

    if (!token.refreshToken) {
      throw new Error('This token didn\'t have a refreshToken. It\'s not possible to refresh this');
    }

    const body: RefreshRequest = {
      grant_type: 'refresh_token',
      refresh_token: token.refreshToken,
    };
    if (!this.settings.clientSecret) {
      // If there's no secret, send the clientId in the body.
      body.client_id = this.settings.clientId;
    }

    return this.tokenResponseToOAuth2Token(this.request('tokenEndpoint', body));

  }

  /**
   * Retrieves an OAuth2 token using the client_credentials grant.
   */
  async clientCredentials(params?: { scope?: string[]; extraParams?: Record<string, string> }): Promise<OAuth2Token> {

    const disallowed = ['client_id', 'client_secret', 'grant_type', 'scope'];

    if (params?.extraParams && Object.keys(params.extraParams).filter((key) => disallowed.includes(key)).length > 0) {
      throw new Error(`The following extraParams are disallowed: '${disallowed.join("', '")}'`);
    }

    const body: ClientCredentialsRequest = {
      grant_type: 'client_credentials',
      scope: params?.scope?.join(' '),
      ...params?.extraParams
    };

    if (!this.settings.clientSecret) {
      throw new Error('A clientSecret must be provided to use client_credentials');
    }

    return this.tokenResponseToOAuth2Token(this.request('tokenEndpoint', body));

  }

  /**
   * Retrieves an OAuth2 token using the 'password' grant'.
   */
  async password(params: { username: string; password: string; scope?: string[] }): Promise<OAuth2Token> {

    const body: PasswordRequest = {
      grant_type: 'password',
      ...params,
      scope: params.scope?.join(' '),
    };
    return this.tokenResponseToOAuth2Token(this.request('tokenEndpoint', body));

  }

  /**
   * Returns the helper object for the `authorization_code` grant.
   */
  get authorizationCode(): OAuth2AuthorizationCodeClient {

    return new OAuth2AuthorizationCodeClient(
      this,
    );

  }

  /**
   * End session
   *
   * This method, in conjunction with the back and front-channel logout notification protocols,
   * enables an OpenID provider together with participating applications to implement single logout.
   *
   * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
   */
  async endSession(settings?: EndSessionRequest): Promise<void> {

    const body: EndSessionRequest = {
      client_id: this.settings.clientId,
      ...(settings ?? {})
    };
    return this.request('endSessionEndpoint', body);

  }

  /**
   * Introspect a token
   *
   * This will give information about the validity, owner, which client
   * created the token and more.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc7662
   */
  async introspect(token: OAuth2Token): Promise<IntrospectionResponse> {

    const body: IntrospectionRequest = {
      token: token.accessToken,
      token_type_hint: 'access_token',
    };
    return this.request('introspectionEndpoint', body);

  }

  /**
   * Returns a url for an OAuth2/OpenID endpoint.
   *
   * Potentially fetches a discovery document to get it.
   */
  getEndpoint(endpoint: OAuth2Endpoint): string {
    try {

      if (this.settings[endpoint] !== undefined) {
        return this.settings[endpoint] as string;
      }
      throw new Error(`Could not determine the location of ${endpoint}.`);
    }catch (e) {
      console.error(e);
      return '';
    }
  }

  /**
   * Fetches the OAuth2/OpenID discovery document
   */
  async receiveEndpoints(): Promise<void> {
    const resp = await this.settings.fetch!(this.settings.discoveryEndpoint!, { headers: { Accept: 'application/json' }});
    if (!resp.ok) return;
    if (!resp.headers.get('Content-Type')?.startsWith('application/json')) {
      console.warn('[oauth2] OAuth2 discovery endpoint was not a JSON response. Response is ignored');
      return;
    }
    const serverMetadata = await resp.json();
    for (const key in ENDPOINTS) {
      const endpoint = ENDPOINTS[key as OAuth2Endpoint] as OAuth2EndpointKey;
      if (!serverMetadata[endpoint]) continue;
      this.settings[key as OAuth2Endpoint] = resolve(serverMetadata[endpoint]!, this.settings.server);
    }

    if (serverMetadata.token_endpoint_auth_methods_supported && !this.settings.authenticationMethod) {
      this.settings.authenticationMethod = serverMetadata.token_endpoint_auth_methods_supported[0];
    }
  }

  /**
   * Does a HTTP request on the 'token' endpoint.
   */
  async request(endpoint: 'tokenEndpoint', body: RefreshRequest | ClientCredentialsRequest | PasswordRequest | AuthorizationCodeRequest): Promise<TokenResponse>;
  async request(endpoint: 'introspectionEndpoint', body: IntrospectionRequest): Promise<IntrospectionResponse>;
  async request(endpoint: 'endSessionEndpoint', body: EndSessionRequest): Promise<void>;
  async request(endpoint: OAuth2Endpoint, body: Record<string, any>): Promise<unknown> {

    const uri = await this.getEndpoint(endpoint);

    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    let authMethod = this.settings.authenticationMethod;

    if (!this.settings.clientSecret) {
      // Basic auth should only be used when there's a client_secret, for
      // non-confidential clients we may only have a client_id, which
      // always gets added to the body.
      authMethod = 'client_secret_post';
    }
    if (!authMethod) {
      // If we got here, it means no preference was provided by anything,
      // and we have a secret. In this case its preferred to embed
      // authentication in the Authorization header.
      authMethod = 'client_secret_basic';
    }

    switch(authMethod) {
      case 'client_secret_basic' :
        headers.Authorization = 'Basic ' +
          btoa(this.settings.clientId + ':' + this.settings.clientSecret);
        break;
      case 'client_secret_post' :
        body.client_id = this.settings.clientId;
        if (this.settings.clientSecret) {
          body.client_secret = this.settings.clientSecret;
        }
        break;
      default:
        throw new Error('Authentication method not yet supported:' + authMethod + '. Open a feature request if you want this!');
    }

    const resp = await this.settings.fetch!(uri, {
      method: 'POST',
      body: generateQueryString(body),
      headers,
      credentials: this.settings.credentials
    });

    if (resp.ok) {
      try {
        return await resp.json();
      } catch (e) {
        return;
      }
    }

    let jsonError;
    let errorMessage;
    let oauth2Code;
    if (resp.headers.has('Content-Type') && resp.headers.get('Content-Type')!.startsWith('application/json')) {
      jsonError = await resp.json();
    }

    if (jsonError?.error) {
      // This is likely an OAUth2-formatted error
      errorMessage = 'OAuth2 error ' + jsonError.error + '.';
      if (jsonError.error_description) {
        errorMessage += ' ' + jsonError.error_description;
      }
      oauth2Code = jsonError.error;

    } else {
      errorMessage = 'HTTP Error ' + resp.status + ' ' + resp.statusText;
      if (resp.status === 401 && this.settings.clientSecret) {
        errorMessage += '. It\'s likely that the clientId and/or clientSecret was incorrect';
      }
      oauth2Code = null;
    }
    throw new OAuth2Error(errorMessage, oauth2Code, resp.status);
  }

  /**
   * Converts the JSON response body from the token endpoint to an OAuth2Token type.
   */
  tokenResponseToOAuth2Token(resp: Promise<TokenResponse>): Promise<OAuth2Token> {

    return resp.then(body => ({
      accessToken: body.access_token,
      expiresAt: body.expires_in ? Date.now() + (body.expires_in * 1000) : null,
      refreshToken: body.refresh_token ?? null,
    }));

  }

}

function resolve(uri: string, base?: string): string {

  return new URL(uri, base).toString();

}

/**
 * Generates a query string.
 *
 * This function filters out any undefined values.
 */
export function generateQueryString(params: Record<string, undefined | number | string>): string {

  return new URLSearchParams(
    Object.fromEntries(
      Object.entries(params).filter(([k, v]) => v !== undefined)
    ) as Record<string, string>
  ).toString();

}
