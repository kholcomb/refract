"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SEVERITY_ORDER = void 0;
exports.bySeverity = bySeverity;
exports.severityAtOrAbove = severityAtOrAbove;
exports.SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
function bySeverity(a, b) {
    return exports.SEVERITY_ORDER.indexOf(a.severity) - exports.SEVERITY_ORDER.indexOf(b.severity);
}
function severityAtOrAbove(severity, threshold) {
    return exports.SEVERITY_ORDER.indexOf(severity) <= exports.SEVERITY_ORDER.indexOf(threshold);
}
//# sourceMappingURL=severity.js.map