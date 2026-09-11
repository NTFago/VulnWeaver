import { registerHooks } from 'node:module';
// Node 24 strips TS; resolve the same extensionless local imports as Vite.
registerHooks({ resolve(specifier, context, nextResolve) {
  try { return nextResolve(specifier, context); }
  catch (error) {
    if (error.code === 'ERR_MODULE_NOT_FOUND' && specifier.startsWith('.')) return nextResolve(specifier + '.ts', context);
    throw error;
  }
} });
