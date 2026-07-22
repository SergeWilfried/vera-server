// Expo config plugin. The remote-access checks (DisplayManager extra displays,
// reading ENABLED_ACCESSIBILITY_SERVICES) need no runtime permission and no
// manifest change, so this plugin is intentionally a pass-through — it exists so
// the module can be added to a config-plugins list uniformly, and gives a home
// for any future native project edits.
//
// The bundled Expo module (expo-module.config.json + android/) is picked up by
// autolinking; a dev build (EAS / `expo prebuild`) is required — the native
// screen-share detection cannot run in Expo Go.

/** @param {import('@expo/config-plugins').ExpoConfig} config */
module.exports = function withVeraFraud(config) {
  return config;
};
