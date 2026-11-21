/// Sends the browser tab to [url] (web only). The web app signs in and out
/// with full-page navigations, so the session cookie is set by the server.
void navigateTo(Uri url) =>
    throw UnsupportedError('page navigation exists only on the web');

/// The page's URL (web only).
Uri currentPage() => throw UnsupportedError('there is no page off the web');
