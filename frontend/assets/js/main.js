/**
 * AccessLease — Frontend Core Script
 * Phase: STEP 03 - Real Microsoft Entra ID Authentication
 *
 * Rules:
 * - Pure Vanilla JavaScript (ES6+)
 * - No frontend frameworks (React, Angular, Vue, Next.js, etc.)
 * - No TypeScript in frontend
 * - No fake or misleading mock authentication/data
 */

document.addEventListener('DOMContentLoaded', async () => {
    console.info('[AccessLease] Frontend initialized in STEP 03 mode.');

    // Initialize Microsoft Entra ID Authentication
    if (window.AccessLeaseAuth) {
        await window.AccessLeaseAuth.initialize();
    } else {
        console.error('[AccessLease] AuthManager module (auth.js) failed to load.');
    }
});
