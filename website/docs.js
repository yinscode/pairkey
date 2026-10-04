// Preserve links into the original single-page guide.
if (location.pathname.endsWith('/docs.html')) {
  const destinations = {
    '#quickstart': 'docs/quickstart.html#quickstart',
    '#integration': 'docs/integration.html#integration',
    '#sessions': 'docs/sessions.html#sessions',
    '#jobs': 'docs/api.html#jobs',
    '#status': 'docs/security.html#status',
    '#sources': 'docs/security.html#sources',
  };
  if (destinations[location.hash]) location.replace(destinations[location.hash]);
}
