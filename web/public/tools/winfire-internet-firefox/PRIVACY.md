# WinFIRE Internet Visibility extension

This Firefox package observes top-level HTTP and HTTPS navigations after the user grants host
access and enrolls the browser with a one-time WinFIRE code. It sends a timestamp, browser type,
and URL metadata over HTTPS. The server strips query strings and fragments; the tenant chooses
host-only or path-prefix collection at enrollment. The extension does not collect page contents,
form data, cookies, credentials, POST bodies, or private browsing sessions. The local queue is
bounded and oldest events are discarded when it reaches its limit.

The extension reports navigation metadata and applies only the declarative allow or block rules published by a WinFIRE administrator. It does not inspect page contents or modify requests outside those published rules.
