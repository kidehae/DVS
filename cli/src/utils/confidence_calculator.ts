interface VulnSnippet {
  snippet?: string;
}

export const calculateConfidence = (v: VulnSnippet): number => {
  const snippet = v.snippet?.toLowerCase() || "";

  // Highest confidence: direct unsanitized user input
  if (/\b(req\.body|req\.query|req\.params|req\.cookies|req\.headers)\b/.test(snippet) &&
      !/sanitize|dompurify|escape|xss-clean/.test(snippet)) {
    return 0.99;
  }

  // High confidence: unsanitized but through a variable
  if (!/sanitize|dompurify|escape|xss-clean/.test(snippet)) {
    return 0.95;
  }

  // Medium confidence: partial sanitization detected
  if (/replace\(/.test(snippet) || /strip/.test(snippet)) {
    return 0.85;
  }

  // Lower confidence: possible vulnerability but uncertain
  return 0.7;
}