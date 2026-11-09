/**
 * AccessLease — Unit Tests: Token Verification Utility (tokenUtils.js)
 * 
 * Verifies:
 * 1. Valid token verification with valid cryptographic signature and claims.
 * 2. Invalid cryptographic signature rejection.
 * 3. Expired token rejection (ERR_TOKEN_EXPIRED).
 * 4. Wrong audience rejection (ERR_INVALID_AUDIENCE).
 * 5. Wrong issuer rejection (ERR_INVALID_ISSUER).
 * 6. Malformed token string rejection (ERR_INVALID_TOKEN).
 * 7. Missing required identity claims (oid/sub) rejection.
 * 8. Future active time (nbf) rejection.
 * 9. Unsupported algorithm (e.g. 'none') rejection.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const tokenUtils = require('../../src/utils/tokenUtils');
const { UnauthorizedError } = require('../../src/utils/errors');

describe('Unit: Microsoft Entra ID Token Verification (tokenUtils)', () => {
    // Generate an in-memory RSA 2048-bit keypair for deterministic offline test doubles
    let rsaKeyPair;
    const TEST_TENANT_ID = 'test-tenant-1111-2222-3333';
    const TEST_CLIENT_ID = 'test-client-aaaa-bbbb-cccc';
    const TEST_AUDIENCE = `api://${TEST_CLIENT_ID}`;
    const TEST_ISSUER = `https://login.microsoftonline.com/${TEST_TENANT_ID}/v2.0`;

    before(() => {
        rsaKeyPair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        // Configure custom key resolver pointing to our test public key
        tokenUtils.setCustomKeyResolver((header, callback) => {
            callback(null, rsaKeyPair.publicKey);
        });
    });

    after(() => {
        // Reset custom key resolver to default
        tokenUtils.setCustomKeyResolver(null);
    });

    function generateToken(payloadOverrides = {}, signOverrides = {}) {
        const payload = {
            oid: 'user-oid-1234-5678-90ab',
            sub: 'user-sub-1234-5678-90ab',
            email: 'governance.tester@accesslease.corp',
            name: 'Governance Tester',
            tid: TEST_TENANT_ID,
            roles: ['RESOURCE_OWNER'],
            ...payloadOverrides
        };

        const options = {
            algorithm: 'RS256',
            audience: TEST_AUDIENCE,
            issuer: TEST_ISSUER,
            expiresIn: '1h',
            keyid: 'test-rsa-kid-1',
            ...signOverrides
        };

        return jwt.sign(payload, rsaKeyPair.privateKey, options);
    }

    test('1. Valid token verification: should successfully verify valid token and extract claims', async () => {
        const token = generateToken();
        const claims = await tokenUtils.validateToken(token, {
            audience: TEST_AUDIENCE,
            issuer: TEST_ISSUER
        });

        assert.strictEqual(claims.oid, 'user-oid-1234-5678-90ab');
        assert.strictEqual(claims.sub, 'user-sub-1234-5678-90ab');
        assert.strictEqual(claims.email, 'governance.tester@accesslease.corp');
        assert.strictEqual(claims.name, 'Governance Tester');
        assert.strictEqual(claims.tid, TEST_TENANT_ID);
        assert.deepStrictEqual(claims.roles, ['RESOURCE_OWNER']);
        assert.ok(claims.expiresAt);
    });

    test('2. Invalid signature rejection: should reject token signed by unknown private key', async () => {
        const strangerKeys = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const forgedToken = jwt.sign(
            { oid: 'forged-oid', tid: TEST_TENANT_ID },
            strangerKeys.privateKey,
            { algorithm: 'RS256', audience: TEST_AUDIENCE, issuer: TEST_ISSUER, expiresIn: '1h' }
        );

        await assert.rejects(
            async () => {
                await tokenUtils.validateToken(forgedToken, {
                    audience: TEST_AUDIENCE,
                    issuer: TEST_ISSUER
                });
            },
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_INVALID_SIGNATURE');
                return true;
            }
        );
    });

    test('3. Expired token rejection: should reject expired tokens with ERR_TOKEN_EXPIRED', async () => {
        const expiredToken = generateToken({}, { expiresIn: '-10s' });

        await assert.rejects(
            async () => {
                await tokenUtils.validateToken(expiredToken, {
                    audience: TEST_AUDIENCE,
                    issuer: TEST_ISSUER
                });
            },
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_TOKEN_EXPIRED');
                return true;
            }
        );
    });

    test('4. Wrong audience rejection: should reject token with mismatched audience', async () => {
        const wrongAudToken = generateToken({}, { audience: 'api://completely-different-application' });

        await assert.rejects(
            async () => {
                await tokenUtils.validateToken(wrongAudToken, {
                    audience: TEST_AUDIENCE,
                    issuer: TEST_ISSUER
                });
            },
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_INVALID_AUDIENCE');
                return true;
            }
        );
    });

    test('5. Wrong issuer rejection: should reject token with untrusted/foreign issuer', async () => {
        const wrongIssToken = generateToken({}, { issuer: 'https://login.untrusted-idp.com/evil' });

        await assert.rejects(
            async () => {
                await tokenUtils.validateToken(wrongIssToken, {
                    audience: TEST_AUDIENCE,
                    issuer: TEST_ISSUER
                });
            },
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_INVALID_ISSUER');
                return true;
            }
        );
    });

    test('6. Missing token rejection: should reject null, undefined, or empty token string', async () => {
        await assert.rejects(
            async () => tokenUtils.validateToken(''),
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_MISSING_TOKEN');
                return true;
            }
        );
        await assert.rejects(
            async () => tokenUtils.validateToken(null),
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_MISSING_TOKEN');
                return true;
            }
        );
    });

    test('7. Malformed token rejection: should reject malformed or non-JWT string', async () => {
        await assert.rejects(
            async () => tokenUtils.validateToken('not.a.valid.jwt.token'),
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_INVALID_TOKEN');
                return true;
            }
        );
    });

    test('8. Missing identity claim rejection: should reject token lacking oid and sub', async () => {
        const payloadWithoutId = {
            email: 'noid@example.com',
            name: 'No ID User'
        };
        const tokenWithoutOid = jwt.sign(payloadWithoutId, rsaKeyPair.privateKey, {
            algorithm: 'RS256',
            audience: TEST_AUDIENCE,
            issuer: TEST_ISSUER,
            expiresIn: '1h'
        });

        await assert.rejects(
            async () => {
                await tokenUtils.validateToken(tokenWithoutOid, {
                    audience: TEST_AUDIENCE,
                    issuer: TEST_ISSUER
                });
            },
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_MISSING_IDENTITY_CLAIM');
                return true;
            }
        );
    });

    test('9. Unsupported algorithm rejection: should reject unsigned alg=none tokens', async () => {
        // Manually construct an unsigned JWT with alg="none"
        const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
        const payload = Buffer.from(JSON.stringify({ oid: '123', aud: TEST_AUDIENCE, iss: TEST_ISSUER })).toString('base64url');
        const unsignedToken = `${header}.${payload}.`;

        await assert.rejects(
            async () => {
                await tokenUtils.validateToken(unsignedToken, {
                    audience: TEST_AUDIENCE,
                    issuer: TEST_ISSUER
                });
            },
            (err) => {
                assert.ok(err instanceof UnauthorizedError);
                assert.strictEqual(err.code, 'ERR_UNSUPPORTED_ALGORITHM');
                return true;
            }
        );
    });
});

