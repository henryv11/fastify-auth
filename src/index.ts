/* eslint-disable @typescript-eslint/ban-types */
import httpErrors from '@heviir/http-errors';
import { FastifyInstance, FastifyRequest, preValidationHookHandler, RouteOptions } from 'fastify';
import fp from 'fastify-plugin';
import jwt from 'jsonwebtoken';

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

export default fp(fastifyAuth, { name: 'fastify-auth' });

async function fastifyAuth(
  app: FastifyInstance,
  opts: {
    privateKey?: string | Buffer | Promise<string | Buffer>;
    publicKey: string | Buffer | Promise<string | Buffer>;
    permissions: Permissions | Promise<Permissions>;
  },
) {
  const [permissions, privateKey, publicKey] = await Promise.all([opts.permissions, opts.privateKey, opts.publicKey]);
  app.decorate('auth', {
    decodeToken: decodeToken.bind({ publicKey }),
    encodeToken: encodeToken.bind({ privateKey }),
    permissions,
  });
  app.decorateRequest('token', null);
  app.decorateRequest('tokenError', '');
  app.decorateRequest('getToken', getToken);
  app.addHook('onRoute', handleOnRoute);
}

async function encodeToken(
  this: { privateKey?: string | Buffer },
  { sub, roles, session, name, phone, email }: TokenPayload,
) {
  const privateKey = this.privateKey;
  if (!privateKey) {
    throw new TypeError('private key is needed to encode token');
  }
  return await new Promise<string>((resolve, reject) =>
    jwt.sign({ sub, roles, session, name, phone, email }, privateKey, ENCODING_OPTIONS, (err, encoded) => {
      if (err || !encoded) {
        return reject(err || new Error('failed to encode token'));
      }
      resolve(encoded);
    }),
  );
}

async function decodeToken(this: { publicKey: string | Buffer }, token?: string) {
  if (!token) {
    throw new Error('missing token');
  }
  return await new Promise<DecodedTokenPayload>((resolve, reject) =>
    jwt.verify(token, this.publicKey, DECODING_OPTIONS, (err, decoded) => {
      if (err || !decoded) {
        return reject(err || new Error('failed to decode token'));
      }
      if (!isRawDecodedTokenPayload(decoded)) {
        return reject(new Error('invalid token payload'));
      }
      resolve({ ...decoded, roles: new Set(decoded.roles) });
    }),
  );
}

function isRawDecodedTokenPayload(token: {}): token is RawDecodedTokenPayload {
  return !['roles', 'sub', 'session', 'iat'].some(key => token[<keyof typeof token>key] == null);
}

async function getToken(this: FastifyRequest): Promise<DecodedTokenPayload> {
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

function handleOnRoute(this: FastifyInstance, routeOptions: RouteOptions) {
  const options = routeOptions.auth;
  if (!options) {
    return;
  }
  const strategy = getStrategy(options);
  mergeSchema(routeOptions);
  routeOptions.preValidation = (<preValidationHookHandler[]>[]).concat(async req => {
    const token = await req.getToken();
    strategy(req, token);
  }, routeOptions.preValidation || []);
}

function getStrategy(
  options: NonNullable<RouteOptions['auth']>,
): (req: FastifyRequest, token: NonNullable<FastifyRequest['token']>) => void {
  switch (typeof options) {
    case 'string':
      const [resourceOrRole, operation] = options.split(':');
      if (resourceOrRole) {
        if (operation) {
          return (req, token) => {
            const resourcePermissions = req.server.auth.permissions[resourceOrRole][<Operation>operation];
            if (resourcePermissions === '*') {
              return;
            }
            if (!resourcePermissions?.some(role => token.roles.has(role))) {
              throw new httpErrors.Forbidden(`missing permission to ${operation} resource`);
            }
          };
        }
        return (_, token) => {
          if (!token.roles.has(resourceOrRole)) {
            throw new httpErrors.Forbidden(`missing required role`);
          }
        };
      }
      throw new TypeError(`invalid endpoint auth options ${options}, expected <resource>:<operation> or <role>`);
    case 'boolean':
      return () => void 0;
    default:
      throw new TypeError(`invalid endpoint auth options type ${typeof options}`);
  }
}

function mergeSchema(routeOptions: RouteOptions) {
  routeOptions.schema = {
    ...routeOptions.schema,
    headers: {
      ...(<{ headers: {} }>routeOptions.schema?.headers),
      type: 'object',
      required: ((<{ required: string[] }>routeOptions.schema?.headers)?.required || []).concat(TOKEN_HEADER_KEY),
      properties: {
        ...(<{ properties: {} }>routeOptions.schema?.headers)?.properties,
        [TOKEN_HEADER_KEY]: TOKEN_SCHEMA,
      },
    },
  };
}

export interface TokenPayload {
  sub: string;
  roles: string[];
  session: string;
  name?: string;
  phone?: string;
  email?: string;
}

export interface RawDecodedTokenPayload extends TokenPayload {
  iat: number;
}

export interface DecodedTokenPayload extends Omit<RawDecodedTokenPayload, 'roles'> {
  roles: Set<string>;
}

export type Operation = 'create' | 'read' | 'update' | 'delete';

export interface Permissions {
  [resource: string]: Partial<Record<Operation, string[] | '*'>>;
}

export type AuthConfig = string | boolean;

declare module 'fastify' {
  interface FastifyInstance {
    auth: {
      decodeToken: OmitThisParameter<typeof decodeToken>;
      encodeToken: OmitThisParameter<typeof encodeToken>;
      permissions: Permissions;
    };
  }

  interface FastifyRequest {
    token: DecodedTokenPayload | null;
    tokenError: string | '';
    getToken: OmitThisParameter<typeof getToken>;
  }

  interface RouteOptions {
    auth?: AuthConfig;
  }

  interface RouteShorthandOptions {
    auth?: AuthConfig;
  }
}
