/**
 * AccessLease — Identity Provisioning Script
 * Provisions an authorized Microsoft Entra user identity in dbo.users and assigns RBAC roles.
 */

const { getPool, closePool } = require('../src/config/database');
const userRepository = require('../src/repositories/userRepository');
const roleRepository = require('../src/repositories/roleRepository');
const logger = require('../src/utils/logger');

async function provisionUser() {
    const entraObjectId = 'f2bba284-9dba-4570-b865-875a009870ed';
    const email = 'shuklaabhayas0@gmail.com';
    const firstName = 'Abhay';
    const lastName = 'Shukla';
    const displayName = 'Abhay Shukla';
    const userType = 'INTERNAL_EMPLOYEE';
    const department = 'Identity & Access Management';

    console.log(`[Provisioning] Connecting to database...`);
    const pool = await getPool();

    try {
        // 1. Check if user already exists by Entra OID
        let user = await userRepository.findUserByEntraObjectId(entraObjectId);

        if (!user) {
            console.log(`[Provisioning] User ${entraObjectId} not found. Creating user in dbo.users...`);
            user = await userRepository.createUser({
                entraObjectId,
                email,
                firstName,
                lastName,
                displayName,
                userType,
                department,
                isActive: true
            });
            console.log(`[Provisioning] User created successfully:`, {
                userId: user.user_id,
                displayName: user.display_name,
                email: user.email
            });
        } else {
            console.log(`[Provisioning] User already exists in dbo.users:`, {
                userId: user.user_id,
                displayName: user.display_name,
                email: user.email,
                isActive: user.is_active
            });

            // Ensure active if deactivated
            if (!user.is_active) {
                await pool.request()
                    .input('userId', user.user_id)
                    .query(`UPDATE dbo.users SET is_active = 1, updated_at = SYSDATETIMEOFFSET() WHERE user_id = @userId`);
                console.log(`[Provisioning] User reactivated.`);
            }
        }

        // 2. Assign SYSTEM_ADMIN and INTERNAL_SPONSOR roles
        const systemAdminRole = await roleRepository.findRoleByCode('SYSTEM_ADMIN');
        const sponsorRole = await roleRepository.findRoleByCode('INTERNAL_SPONSOR');

        if (systemAdminRole) {
            await roleRepository.assignRoleToUser(user.user_id, systemAdminRole.role_id);
            console.log(`[Provisioning] Role assigned: SYSTEM_ADMIN (ID: ${systemAdminRole.role_id})`);
        }

        if (sponsorRole) {
            await roleRepository.assignRoleToUser(user.user_id, sponsorRole.role_id);
            console.log(`[Provisioning] Role assigned: INTERNAL_SPONSOR (ID: ${sponsorRole.role_id})`);
        }

        // Seed roles for test identities
        const seededSponsor = await userRepository.findUserByEntraObjectId('TEST-OID-SPONSOR');
        if (seededSponsor && sponsorRole) {
            await roleRepository.assignRoleToUser(seededSponsor.user_id, sponsorRole.role_id);
            console.log(`[Provisioning] Assigned INTERNAL_SPONSOR to TEST-OID-SPONSOR`);
        }

        const seededContractor = await userRepository.findUserByEntraObjectId('TEST-OID-CONTRACTOR');
        const contractorRole = await roleRepository.findRoleByCode('CONTRACTOR');
        if (seededContractor && contractorRole) {
            await roleRepository.assignRoleToUser(seededContractor.user_id, contractorRole.role_id);
            console.log(`[Provisioning] Assigned CONTRACTOR to TEST-OID-CONTRACTOR`);
        }

        // 3. Verify user and roles
        const assignedRoles = await roleRepository.getUserRoles(user.user_id);
        console.log(`[Provisioning] Verification complete. Current roles:`, assignedRoles.map(r => r.role_code));

    } catch (err) {
        console.error(`[Provisioning] Error:`, err);
        throw err;
    } finally {
        await closePool();
    }
}

provisionUser()
    .then(() => {
        console.log('[Provisioning] Success!');
        process.exit(0);
    })
    .catch((err) => {
        console.error('[Provisioning] Failed:', err);
        process.exit(1);
    });

