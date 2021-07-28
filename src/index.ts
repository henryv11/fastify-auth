import httpErrors from '@heviir/http-errors';
import { FastifyInstance, FastifyRequest, preValidationHookHandler, RouteOptions } from 'fastify';
import fp from 'fastify-plugin';
import * as jwt from 'jsonwebtoken';

const TOKEN_HEADER_KEY = 'authorization';
const ALGORITHM: jwt.Algorithm = 'RS512';
const ISSUER = 'heviir/authorization';
const JWT_ID = 'jwt_id';
const ENCODING_OPTIONS: jwt.SignOptions = {
  algorithm: ALGORITHM,
  issuer: ISSUER,
  jwtid: JWT_ID,
  expiresIn: 600000,
};
const DECODING_OPTIONS: jwt.VerifyOptions = {
  algorithms: [ALGORITHM],
  issuer: [ISSUER],
  jwtid: JWT_ID,
  clockTolerance: 1000,
};
const TOKEN_SCHEMA = {
  type: 'string',
  example:
    'Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0IiwiaWF0IjoxNjAxODE0Mzc4fQ.Cqo8aBPhJN-hVN9wpAYNnIbLZ8M8ORMAMj_6ZIQTGV_g1hx3dti5Qjelgup2eh2dEnbP3aNmLqHKA7vYrJZjBQ',
  description: 'JSON Web Token in format "Bearer [token]',
};

export default fp(
  async function fastifyAuth(
    app,
    opts: {
      privateKey?: string | Buffer | Promise<string | Buffer>;
      publicKey: string | Buffer | Promise<string | Buffer>;
      permissions: Permissions | Promise<Permissions>;
    },
  ) {
    const [permissions, privateKey, publicKey] = await Promise.all([opts.permissions, opts.privateKey, opts.publicKey]);
    const auth: FastifyInstance['auth'] = {
      decodeToken: decodeToken.bind({ publicKey }),
      encodeToken: encodeToken.bind({ privateKey }),
      permissions,
    };
    app.decorate('auth', auth);
    app.decorateRequest('token', null);
    app.decorateRequest('tokenError', '');
    app.decorateRequest('getToken', getToken);
    app.addHook('onRoute', handleOnRoute);
  },
  { name: 'fastify-auth' },
);

function handleOnRoute(this: FastifyInstance, routeOptions: RouteOptions) {
  const options = routeOptions.auth;
  if (!options) {
    return;
  }
  const strategy = getStrategy(options, this.auth.permissions);
  mergeSchema(routeOptions);
  routeOptions.preValidation = (<preValidationHookHandler[]>[]).concat(async function (req) {
    const token = await req.getToken();
    strategy(req, token);
  }, routeOptions.preValidation || []);
}

async function encodeToken(this: { privateKey?: string | Buffer }, { sub, roles, session }: TokenPayload) {
  if (!this.privateKey) {
    throw new TypeError('private key is needed to encode token');
  }
  return await new Promise<string>((resolve, reject) =>
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    jwt.sign({ sub, roles, session }, this.privateKey!, ENCODING_OPTIONS, (err, encoded) => {
      if (err || !encoded) {
        reject(err || new Error('failed to encode token'));
      } else {
        resolve(encoded);
      }
    }),
  );
}

async function decodeToken(this: { publicKey: string | Buffer }, token?: string) {
  if (!token) {
    throw new Error('missing token');
  }
  return await new Promise<DecodedToken>((resolve, reject) =>
    jwt.verify(token, this.publicKey, DECODING_OPTIONS, (err, decoded) => {
      if (err || !decoded) {
        reject(err || new Error('failed to decode token'));
      } else {
        const { roles, ...rest } = <RawDecodedToken>decoded;
        resolve(<DecodedToken>{ ...rest, roles: new Set(roles) });
      }
    }),
  );
}

async function getToken(this: FastifyRequest): ReturnType<FastifyRequest['getToken']> {
  if (this.token) {
    return this.token;
  }
  if (this.tokenError) {
    throw new httpErrors.Unauthorized(this.tokenError);
  }
  const rawToken = this.headers[TOKEN_HEADER_KEY]?.split(' ')[1];
  try {
    this.token = await this.server.auth.decodeToken(rawToken);
    return this.token;
  } catch (error) {
    this.tokenError = (<Error>error).message;
    throw new httpErrors.Unauthorized(this.tokenError);
  }
}

function getStrategy(
  options: NonNullable<RouteOptions['auth']>,
  permissions: Permissions,
): (req: FastifyRequest, token: NonNullable<FastifyRequest['token']>) => void {
  switch (typeof options) {
    case 'string':
      const [resource, operation] = options.split(':');
      if (!resource || !operation) {
        throw new TypeError(`invalid endpoint auth options ${options}, expected <resource>:<permission>`);
      }
      return (_, token) => {
        if (!permissions[resource][<Operation>operation]?.some(role => token.roles.has(role))) {
          throw new httpErrors.Forbidden(`user does not have permission to ${operation} resource`);
        }
      };
    case 'boolean':
    case 'object':
      return () => void 0;
    default:
      throw new TypeError(`invalid authorization config type ${typeof options}`);
  }
}

function mergeSchema(routeOptions: RouteOptions) {
  routeOptions.schema = {
    ...routeOptions.schema,
    headers: {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ...(<any>routeOptions.schema?.headers),
      type: 'object',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      required: [...((<any>routeOptions.schema?.headers)?.required || [])].concat(TOKEN_HEADER_KEY),
      properties: {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        ...(<any>routeOptions.schema?.headers)?.properties,
        [TOKEN_HEADER_KEY]: TOKEN_SCHEMA,
      },
    },
  };
}

export interface TokenPayload {
  sub: string;
  roles?: string[];
  session?: string;
}

export interface RawDecodedToken extends TokenPayload {
  iat: number;
}

export interface DecodedToken extends Omit<RawDecodedToken, 'roles'> {
  roles: Set<string>;
}

export type Operation = 'create' | 'read' | 'update' | 'delete';

export interface Permissions {
  [resource: string]: Partial<Record<Operation, string[]>>;
}

export type AuthConfig = string | boolean;

declare module 'fastify' {
  interface FastifyInstance {
    auth: {
      decodeToken: (rawToken?: string) => Promise<DecodedToken>;
      encodeToken: (payload: TokenPayload) => Promise<string>;
      permissions: Permissions;
    };
  }

  interface FastifyRequest {
    token: DecodedToken | null;
    tokenError: string | '';
    getToken: () => Promise<DecodedToken>;
  }

  interface RouteOptions {
    auth?: AuthConfig;
  }

  interface RouteShorthandOptions {
    auth?: AuthConfig;
  }
}
