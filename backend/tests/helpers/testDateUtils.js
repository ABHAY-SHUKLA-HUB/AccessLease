/**
 * AccessLease — Shared Test Date Utilities
 * Generates ISO UTC date-only strings (YYYY-MM-DD) consistent with policyEngine date semantics.
 */

function toDateStr(dateVal) {
    if (!dateVal) return '';
    const d = new Date(dateVal);
    if (isNaN(d.getTime())) return '';
    return d.toISOString().split('T')[0];
}

/**
 * Generates a valid (startDate, endDate) pair in YYYY-MM-DD UTC format.
 * Defaults to starting tomorrow, with 14 days duration.
 * 
 * @param {number} [daysFromNow=1] Days in future for start date (>= 0)
 * @param {number} [durationDays=14] Number of days between start and end date (> 0)
 * @returns {{ startDate: string, endDate: string }}
 */
function getValidTestDates(daysFromNow = 1, durationDays = 14) {
    const now = new Date();
    const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + daysFromNow));
    const end = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate() + durationDays));
    return {
        startDate: toDateStr(start),
        endDate: toDateStr(end)
    };
}

/**
 * Generates a past date string (YYYY-MM-DD) for negative testing.
 * @param {number} [daysInPast=5]
 * @returns {string}
 */
function getPastTestDate(daysInPast = 5) {
    const now = new Date();
    const past = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - daysInPast));
    return toDateStr(past);
}

module.exports = {
    toDateStr,
    getValidTestDates,
    getPastTestDate
};
