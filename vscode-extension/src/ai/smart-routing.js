const COMPLEX_RULES = /authorization|idor|ssrf|deserial|prototype|business.logic/i;

function recommendModelRole({ finding, context, historicalSuccessRate }, options = {}) {
  const maxFastContextChars = options.maxFastContextChars || 6000;
  const maxFastAffectedLines = options.maxFastAffectedLines || 4;
  const minimumHistoricalSuccess = options.minimumHistoricalSuccess ?? 0.75;
  const affectedLines = Math.max(1, Number(finding?.endLine ?? finding?.startLine ?? 0) - Number(finding?.startLine || 0) + 1);
  const reasons = [];
  if (COMPLEX_RULES.test(`${finding?.ruleId || ''} ${finding?.title || ''}`)) reasons.push('complex_rule');
  if (String(context?.excerpt || '').length > maxFastContextChars) reasons.push('large_context');
  if (affectedLines > maxFastAffectedLines) reasons.push('multi_line_change');
  if (context?.contextKinds?.crossFunction === true) reasons.push('cross_function');
  if (Number.isFinite(historicalSuccessRate) && historicalSuccessRate < minimumHistoricalSuccess) reasons.push('low_historical_success');
  return { role: reasons.length ? 'advanced' : 'fast', reasons };
}

module.exports = { recommendModelRole };
