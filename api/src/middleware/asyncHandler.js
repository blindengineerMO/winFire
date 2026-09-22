/** Convert an async route handler into an Express error-forwarding handler. */
export const asyncHandler = handler => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next)
