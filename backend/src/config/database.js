/**
 * AccessLease — Centralized SQL Connection Management
 * Target: Microsoft SQL Server 2019+ / Azure SQL Database
 * Driver: mssql (tedious)
 *
 * Requirements:
 * - Singleton connection pooling (no new pool per request)
 * - Safe parameterization
 * - Zero secret leakage
 * - Automatic LocalDB dynamic pipe resolution for local testing
 * - Clean teardown
 */

const sql = require('mssql');
const net = require('net');
const cp = require('child_process');
const env = require('./environment');
const logger = require('../utils/logger');
const { DatabaseError } = require('../utils/errors');

let poolPromise = null;
let currentPool = null;

/**
 * Resolves the active named pipe for Windows SQL Server LocalDB if configured.
 * @param {string} serverTarget 
 * @returns {string|null}
 */
function resolveLocalDbPipe(serverTarget) {
    if (!serverTarget) return null;
    const lower = serverTarget.toLowerCase();
    if (!lower.includes('(localdb)') && !lower.includes('localdb#') && !lower.startsWith('np:')) {
        return null;
    }

    try {
        // Extract instance name, e.g. "MSSQLLocalDB" from "(localdb)\MSSQLLocalDB"
        const parts = serverTarget.split('\\');
        const instanceName = parts.length > 1 ? parts[1].trim() : 'MSSQLLocalDB';

        // Ensure instance is started
        try {
            cp.execSync(`sqllocaldb start "${instanceName}"`, { stdio: 'pipe' });
        } catch {
            // Already started or start handled by OS
        }

        const infoOut = cp.execSync(`sqllocaldb info "${instanceName}"`, { encoding: 'utf8' });
        const match = infoOut.match(/Instance pipe name:\s*(.*)/i);
        if (match && match[1]) {
            const rawPipe = match[1].trim();
            return rawPipe.replace(/^np:/, '');
        }
    } catch (err) {
        logger.warn('Failed to resolve dynamic LocalDB named pipe', { error: err.message });
    }

    return null;
}

/**
 * Constructs driver connection options based on environment variables.
 * @returns {object} mssql Configuration Object
 */
function buildSqlConfig() {
    const isLocalDb = env.SQL_SERVER.toLowerCase().includes('(localdb)') || 
                      env.SQL_SERVER.toLowerCase().includes('localdb#') ||
                      env.SQL_SERVER.toLowerCase().startsWith('np:');

    const pipePath = isLocalDb ? resolveLocalDbPipe(env.SQL_SERVER) : null;

    const baseConfig = {
        database: env.SQL_DATABASE,
        connectionTimeout: env.SQL_CONNECTION_TIMEOUT,
        requestTimeout: env.SQL_REQUEST_TIMEOUT,
        pool: {
            max: env.SQL_POOL_MAX,
            min: env.SQL_POOL_MIN,
            idleTimeoutMillis: 30000
        },
        options: {
            encrypt: env.SQL_ENCRYPT,
            trustServerCertificate: env.SQL_TRUST_SERVER_CERTIFICATE,
            enableArithAbort: true
        }
    };

    if (pipePath) {
        // LocalDB via Named Pipe (Windows Local Environment)
        logger.info('Configuring SQL driver via Windows Named Pipe for LocalDB');
        baseConfig.server = 'localhost';
        baseConfig.options.encrypt = false;
        baseConfig.options.trustServerCertificate = true;
        baseConfig.options.connector = (opts, lookup, signal) => {
            return new Promise((resolve, reject) => {
                const socket = net.connect(pipePath);
                socket.on('error', reject);
                socket.on('connect', () => resolve(socket));
            });
        };
    } else {
        // Standard TCP/IP (Azure SQL Database or Remote SQL Server)
        baseConfig.server = env.SQL_SERVER;
        baseConfig.port = env.SQL_PORT;
        baseConfig.user = env.SQL_USER;
        baseConfig.password = env.SQL_PASSWORD;
    }

    return baseConfig;
}

/**
 * Returns the singleton connection pool promise.
 * Reuses existing active pool; reconnects if previously closed or disconnected.
 * @returns {Promise<sql.ConnectionPool>}
 */
async function getPool() {
    if (currentPool && currentPool.connected) {
        return currentPool;
    }

    if (!poolPromise) {
        const validation = env.validateDatabaseConfig();
        if (!validation.isValid) {
            const err = new DatabaseError(
                `Database configuration is incomplete. Missing: ${validation.missingFields.join(', ')}`
            );
            logger.error('Database connection aborted due to missing configuration', err);
            throw err;
        }

        const config = buildSqlConfig();

        poolPromise = new sql.ConnectionPool(config)
            .connect()
            .then(pool => {
                logger.info('Database connection pool established successfully', {
                    database: env.SQL_DATABASE,
                    poolMax: env.SQL_POOL_MAX,
                    poolMin: env.SQL_POOL_MIN
                });

                pool.on('error', err => {
                    logger.error('Unexpected error on active database pool connection', err);
                    // Invalidate pool so next query attempts re-connection
                    poolPromise = null;
                    currentPool = null;
                });

                currentPool = pool;
                return pool;
            })
            .catch(err => {
                poolPromise = null;
                currentPool = null;
                logger.error('Failed to establish database connection pool', err);
                throw new DatabaseError('Failed to connect to SQL database.', err);
            });
    }

    return poolPromise;
}

/**
 * Executes a lightweight connectivity check.
 * @returns {Promise<{ is_healthy: boolean, server_time: string }>}
 */
async function checkConnection() {
    const pool = await getPool();
    const result = await pool.request().query('SELECT 1 AS is_healthy, SYSDATETIMEOFFSET() AS server_time');
    
    if (result && result.recordset && result.recordset.length > 0) {
        const row = result.recordset[0];
        return {
            is_healthy: row.is_healthy === 1,
            server_time: row.server_time instanceof Date ? row.server_time.toISOString() : String(row.server_time)
        };
    }

    throw new DatabaseError('Database health check query returned no rows.');
}

/**
 * Executes a parameterized SQL query safely.
 * @param {string} queryText T-SQL Query Text
 * @param {object} params Key-value pairs for parameters
 * @returns {Promise<sql.IResult<any>>}
 */
async function query(queryText, params = {}) {
    const pool = await getPool();
    const request = pool.request();

    for (const [key, val] of Object.entries(params)) {
        if (val !== null && typeof val === 'object' && val.type) {
            request.input(key, val.type, val.value);
        } else {
            request.input(key, val);
        }
    }

    return request.query(queryText);
}

/**
 * Closes the active connection pool cleanly.
 * Useful for graceful shutdown and isolated test teardown.
 * @returns {Promise<void>}
 */
async function closePool() {
    if (currentPool) {
        try {
            await currentPool.close();
            logger.info('Database connection pool closed cleanly');
        } catch (err) {
            logger.warn('Error while closing database connection pool', { error: err.message });
        } finally {
            currentPool = null;
            poolPromise = null;
        }
    }
}

module.exports = {
    getPool,
    checkConnection,
    query,
    closePool,
    buildSqlConfig,
    resolveLocalDbPipe
};

