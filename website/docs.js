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

// Keep the current page visible inside the independently scrolling desktop menu.
if (matchMedia('(min-width: 701px)').matches) {
  const nav = document.querySelector('.docs-nav');
  const current = nav?.querySelector('[aria-current="page"]');
  if (current && nav.scrollHeight > nav.clientHeight) {
    const link = current.getBoundingClientRect();
    const viewport = nav.getBoundingClientRect();
    if (link.bottom > viewport.bottom) nav.scrollTop += link.bottom - viewport.bottom + 8;
    if (link.top < viewport.top) nav.scrollTop -= viewport.top - link.top + 8;
  }
}
