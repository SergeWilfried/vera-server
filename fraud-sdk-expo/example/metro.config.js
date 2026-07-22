// Resolve @veratools/fraud-sdk-expo to the SDK's TypeScript source next door, so
// this example runs the SDK without a separate build step. Metro/Babel transpile
// the source (it lives under watchFolders, outside node_modules), and the SDK's
// react-native / expo-* imports resolve from THIS app's node_modules.
const { getDefaultConfig } = require('expo/metro-config');
const path = require('path');

const projectRoot = __dirname;
const sdkRoot = path.resolve(projectRoot, '..'); // fraud-sdk-expo
const sdkEntry = path.resolve(sdkRoot, 'src/index.ts');

const config = getDefaultConfig(projectRoot);

config.watchFolders = [sdkRoot];
config.resolver.nodeModulesPaths = [path.resolve(projectRoot, 'node_modules')];

const baseResolveRequest = config.resolver.resolveRequest;
config.resolver.resolveRequest = (context, moduleName, platform) => {
  if (moduleName === '@veratools/fraud-sdk-expo') {
    return { type: 'sourceFile', filePath: sdkEntry };
  }
  return (baseResolveRequest ?? context.resolveRequest)(context, moduleName, platform);
};

module.exports = config;
