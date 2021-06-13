import httpErrors from '@heviir/http-errors';
import { FastifyInstance, FastifyRequest, preValidationHookHandler } from 'fastify';
import fp from 'fastify-plugin';
import * as jwt from 'jsonwebtoken';

const TOKEN_HEADER_KEY = 'authorization';
const TOKEN_EXAMPLE =
  'Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0IiwiaWF0IjoxNjAxODE0Mzc4fQ.Cqo8aBPhJN-hVN9wpAYNnIbLZ8M8ORMAMj_6ZIQTGV_g1hx3dti5Qjelgup2eh2dEnbP3aNmLqHKA7vYrJZjBQ';
const TOKEN_DESCRIPTION = 'JSON Web Token in format "Bearer [token]';
const ALGORITHM = 'RS512';
const ISSUER = 'heviir/authorization';
const JWT_ID = 'jwt_id';

export default fp(
  async function fastifyAuth(
    app,
    {
      privateKey: maybePrivateKeyPromise,
      publicKey: maybePublicKeyPromise,
      permissions: maybePermissionsPromise,
    }: {
      /**
       * @param privateKey to encode token, only needed for auth server
       */
      privateKey?: string | Buffer | Promise<string | Buffer>;
      /**
       * @param publicKey to decode token
       */
      publicKey: string | Buffer | Promise<string | Buffer>;
      /**
       * @param permissions from auth server
       */
      permissions: Permissions | Promise<Permissions>;
    },
  ) {
    const [permissions, privateKey, publicKey] = await Promise.all([
      maybePermissionsPromise,
      maybePrivateKeyPromise,
      maybePublicKeyPromise,
    ]);
    app.decorate(
      'auth',
      Object.freeze<FastifyInstance['auth']>({
        decodeToken(token) {
          if (!token) return Promise.reject(Error('missing token'));
          return new Promise<DecodedToken>((resolve, reject) =>
            jwt.verify(token, publicKey, { algorithms: [ALGORITHM], issuer: [ISSUER], jwtid: JWT_ID }, (err, decoded) =>
              err || !decoded
                ? reject(err || new Error('failed to decode token'))
                : resolve(<DecodedToken>{ ...decoded, roles: new Set((<RawDecodedToken>decoded).roles) }),
            ),
          );
        },
        encodeToken({ roles, sub, session }) {
          if (!privateKey) return Promise.reject(new TypeError('private key is needed to encode token'));
          return new Promise((resolve, reject) =>
            jwt.sign(
              { sub, roles, session },
              privateKey,
              { algorithm: ALGORITHM, issuer: ISSUER, expiresIn: '12h', jwtid: JWT_ID },
              (err, encoded) =>
                err || !encoded ? reject(err || new Error('failed to encode token')) : resolve(encoded),
            ),
          );
        },
      }),
    );
    app.decorateRequest('token', null);
    app.decorateRequest('tokenError', '');
    app.decorateRequest('getToken', async function (this: FastifyRequest): ReturnType<FastifyRequest['getToken']> {
      const result = { token: this.token, error: this.tokenError };
      if (result.token || result.error) return result;
      const rawToken = this.headers[TOKEN_HEADER_KEY]?.split(' ')[1];
      try {
        result.token = this.token = await app.auth.decodeToken(rawToken);
      } catch (error) {
        result.error = this.tokenError = error.message;
      }
      return result;
    });
    app.addHook('onRoute', function (routeOptions) {
      const options = routeOptions.auth;
      if (!options) return;
      let strategy: (req: FastifyRequest, token: NonNullable<FastifyRequest['token']>) => void;
      switch (typeof options) {
        case 'string':
          const [resource, operation] = (<string>options).split(':');
          if (!permissions[resource]) throw new TypeError('invalid resource ' + resource);
          const resourcePermissions = permissions[resource][<Operation>operation];
          if (!resourcePermissions) throw new TypeError('invalid operation ' + operation);
          strategy = (_, token) => {
            if (!resourcePermissions.some(role => token.roles.has(role)))
              throw new httpErrors.Forbidden({ response: 'lacking permission to ' + operation + ' resource' });
          };
          break;
        case 'boolean':
        case 'object':
          strategy = () => void 0;
          break;
        default:
          throw new TypeError('invalid authorization config type ' + typeof options);
      }
      routeOptions.schema = {
        ...routeOptions.schema,
        headers: {
          /* eslint-disable @typescript-eslint/no-explicit-any */
          ...(<any>routeOptions.schema?.headers),
          type: 'object',
          required: [...((<any>routeOptions.schema?.headers)?.required || [])].concat(TOKEN_HEADER_KEY),
          properties: {
            ...(<any>routeOptions.schema?.headers)?.properties,
            /* eslint-enable @typescript-eslint/no-explicit-any */
            [TOKEN_HEADER_KEY]: {
              type: 'string',
              example: TOKEN_EXAMPLE,
              description: TOKEN_DESCRIPTION,
            },
          },
        },
      };
      routeOptions.preValidation = (<preValidationHookHandler[]>[]).concat(async function (req) {
        const { error, token } = await req.getToken();
        if (!token) throw new httpErrors.Unauthorized({ response: error });
        strategy(req, token);
      }, routeOptions.preValidation || []);
    });
  },
  { name: 'fastify-auth' },
);

export interface TokenPayload {
  sub: string | number;
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
      decodeToken: (token?: string) => Promise<NonNullable<FastifyRequest['token']>>;
      encodeToken: (payload: TokenPayload) => Promise<string>;
    };
  }

  interface FastifyRequest {
    token: DecodedToken | null;
    tokenError: string | '';
    getToken: () => Promise<{ token: FastifyRequest['token']; error: FastifyRequest['tokenError'] }>;
    ensureToken: () => DecodedToken;
  }

  interface RouteOptions {
    auth?: AuthConfig;
  }
  interface RouteShorthandOptions {
    auth?: AuthConfig;
  }
}
