# Web assets

Runtime brand images and downloadable tools are served from `web/public` so the
single-port Express server can expose them without bundling binary files into
route components. New UI-only assets belong here when they need import-time
hashing; shared brand assets stay in `public`.
