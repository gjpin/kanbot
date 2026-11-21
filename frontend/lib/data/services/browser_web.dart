import 'dart:js_interop';

@JS('window.location.assign')
external void _assign(String url);

/// Sends the browser tab to [url]. The web app signs in and out with
/// full-page navigations, so the session cookie is set by the server.
void navigateTo(Uri url) => _assign(url.toString());

/// The page's URL.
Uri currentPage() => Uri.base;
