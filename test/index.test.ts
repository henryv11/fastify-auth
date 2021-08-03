import fastify from 'fastify';
import { readFile as readFileFS } from 'fs';
import { promisify } from 'util';
import fastifyAuth from '../src';

const readFile = promisify(readFileFS);

function getApp() {
  const app = fastify({
    logger: !true,
  });
  app.register(fastifyAuth, {
    privateKey: readFile(__dirname + '/privateKey.pem'),
    publicKey: readFile(__dirname + '/publicKey.pem'),
    permissions: {
      hello: {
        read: ['user', 'admin'],
        create: ['admin'],
        update: ['admin'],
      },
    },
  });
  return app;
}

describe('fastify auth', () => {
  test('it works', async () => {
    const app = getApp();
    app.get('/', {
      auth: 'hello:read',
      handler: (req, res) => {
        res.send(req.token);
      },
    });
    await app.ready();
    const makeReq = async (token?: string | Promise<string>) =>
      app.inject({ method: 'GET', path: '/', headers: { ...(token && { authorization: 'bearer ' + (await token) }) } });

    let res = await makeReq();
    expect(res.json().message).toEqual('Unauthorized');

    res = await makeReq(app.auth.encodeToken({ sub: 'blin', roles: ['user'], session: '' }));
    expect(res.json().sub).toEqual('blin');

    res = await makeReq(await app.auth.encodeToken({ sub: 'blin', roles: [], session: '' }));
    expect(res.json().message).toEqual('Forbidden');
  });
});
